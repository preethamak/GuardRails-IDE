use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use guardrails_fs_broker::{AuditEvent, MemoryAuditSink, WorkspaceBroker};
use guardrails_policy::{Approval, Capability, Effect, Grant, Request};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    env, fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");
const MAX_INDEX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    workspace_name: String,
    files: Vec<String>,
    broker: WorkspaceBroker<MemoryAuditSink>,
    audit: MemoryAuditSink,
    grants: Vec<Grant>,
    request_sequence: AtomicU64,
}

#[derive(Serialize)]
struct WorkspaceResponse {
    name: String,
    files: Vec<String>,
    security: SecuritySummary,
}

#[derive(Serialize)]
struct SecuritySummary {
    binding: &'static str,
    max_file_bytes: u64,
    hidden_files: &'static str,
    policy: &'static str,
}

#[derive(Deserialize)]
struct FileQuery {
    path: String,
}

#[derive(Serialize)]
struct FileResponse {
    path: String,
    content: String,
    request_id: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
    request_id: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse(env::args().skip(1))?;
    let state = build_state(&config.workspace)?;
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
    println!("GuardRails IDE: http://{address}");
    println!("Workspace: {}", config.workspace.display());
    println!("Press Ctrl+C to stop.");

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address).await?;
        axum::serve(listener, app(state))
            .with_graceful_shutdown(shutdown_signal())
            .await
    })?;
    Ok(())
}

struct Config {
    workspace: PathBuf,
    port: u16,
}

impl Config {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut workspace = env::current_dir().map_err(|error| error.to_string())?;
        let mut port = 43110;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--workspace" => {
                    workspace = PathBuf::from(args.next().ok_or("--workspace needs a path")?);
                }
                "--port" => {
                    port = args
                        .next()
                        .ok_or("--port needs a number")?
                        .parse()
                        .map_err(|_| "--port must be between 1 and 65535")?;
                }
                "--help" | "-h" => {
                    return Err("usage: guardrails-ide [--workspace PATH] [--port PORT]".into());
                }
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        if !workspace.is_dir() {
            return Err(format!(
                "workspace is not a directory: {}",
                workspace.display()
            ));
        }
        Ok(Self { workspace, port })
    }
}

fn build_state(workspace: &Path) -> io::Result<AppState> {
    let workspace = fs::canonicalize(workspace)?;
    let workspace_name = workspace
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace")
        .to_owned();
    let files = index_workspace(&workspace);
    let audit = MemoryAuditSink::default();
    let broker = WorkspaceBroker::open(&workspace, audit.clone(), MAX_FILE_BYTES)?;
    let principal = "user:local-web";
    let workspace_id = format!("local:{workspace_name}");
    let allow = Grant {
        id: "local-workspace-read".into(),
        principal_id: principal.into(),
        workspace_id: workspace_id.clone(),
        capability: Capability::Filesystem,
        actions: BTreeSet::from(["read".into()]),
        resource_pattern: "workspace/**".into(),
        effect: Effect::Allow,
        approval: Approval::Automatic,
        expires_at_ms: None,
    };
    Ok(AppState {
        inner: Arc::new(AppStateInner {
            workspace_name,
            files,
            broker,
            audit,
            grants: vec![allow],
            request_sequence: AtomicU64::new(1),
        }),
    })
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .route("/app.js", get(script))
        .route("/app.css", get(styles))
        .route("/api/workspace", get(workspace))
        .route("/api/file", get(read_file))
        .route("/api/audit", get(audit))
        .fallback(not_found)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn styles() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn workspace(State(state): State<AppState>) -> Json<WorkspaceResponse> {
    Json(WorkspaceResponse {
        name: state.inner.workspace_name.clone(),
        files: state.inner.files.clone(),
        security: SecuritySummary {
            binding: "127.0.0.1 only",
            max_file_bytes: MAX_FILE_BYTES,
            hidden_files: "excluded from index",
            policy: "deny by default",
        },
    })
}

async fn read_file(State(state): State<AppState>, Query(query): Query<FileQuery>) -> Response {
    if state.inner.files.binary_search(&query.path).is_err() || !safe_relative_path(&query.path) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "file is not in the approved workspace index",
                request_id: None,
            }),
        )
            .into_response();
    }
    let sequence = state.inner.request_sequence.fetch_add(1, Ordering::Relaxed);
    let request_id = format!("web-{sequence}");
    let request = Request {
        id: request_id.clone(),
        principal_id: "user:local-web".into(),
        workspace_id: format!("local:{}", state.inner.workspace_name),
        capability: Capability::Filesystem,
        action: "read".into(),
        resource: format!("workspace/{}", query.path),
        requested_at_ms: now_ms(),
    };
    match state.inner.broker.read(&request, &state.inner.grants) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(content) => Json(FileResponse {
                path: query.path,
                content,
                request_id,
            })
            .into_response(),
            Err(_) => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(ErrorResponse {
                    error: "binary files are not displayed",
                    request_id: Some(request_id),
                }),
            )
                .into_response(),
        },
        Err(_) => (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "broker denied the file request",
                request_id: Some(request_id),
            }),
        )
            .into_response(),
    }
}

async fn audit(State(state): State<AppState>) -> Json<Vec<AuditEvent>> {
    Json(state.inner.audit.events())
}

async fn not_found() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}

fn index_workspace(root: &Path) -> Vec<String> {
    let mut files: Vec<String> = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true)
        .follow_links(false)
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .filter_map(|entry| entry.path().strip_prefix(root).ok().map(Path::to_owned))
        .filter(|path| safe_relative_path(&path.to_string_lossy()))
        .take(MAX_INDEX_FILES)
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect();
    files.sort_unstable();
    files
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && Path::new(value).components().all(|component| {
            matches!(component, Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
        })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_app() -> (Router, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.path().join(".env"), "TOKEN=secret\n").unwrap();
        fs::write(root.path().join(".git/config"), "credential=secret\n").unwrap();
        (app(build_state(root.path()).unwrap()), root)
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn serves_workspace_without_hidden_files_and_with_security_headers() {
        let (app, _root) = test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/workspace")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(
            response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        let value = body_json(response).await;
        assert_eq!(value["files"], serde_json::json!(["src/main.rs"]));
        assert_eq!(value["security"]["policy"], "deny by default");
    }

    #[tokio::test]
    async fn reads_indexed_source_through_broker_then_exposes_audit_event() {
        let (app, _root) = test_app();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/file?path=src%2Fmain.rs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response).await;
        assert_eq!(value["content"], "fn main() {}\n");

        let audit_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let events = body_json(audit_response).await;
        assert_eq!(events[0]["principal_id"], "user:local-web");
        assert_eq!(events[0]["resource"], "workspace/src/main.rs");
        assert_eq!(events[0]["outcome"], "allow");
    }

    #[tokio::test]
    async fn rejects_hidden_traversal_and_unindexed_paths_before_broker() {
        let (app, _root) = test_app();
        for path in [".env", "../.env", ".git/config", "missing.rs"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/file?path={}", path.replace('/', "%2F")))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    #[test]
    fn config_defaults_to_current_directory_and_rejects_unknown_flags() {
        let config = Config::parse(Vec::<String>::new().into_iter()).unwrap();
        assert!(config.workspace.is_dir());
        assert_eq!(config.port, 43110);
        assert!(Config::parse(["--unsafe".to_owned()].into_iter()).is_err());
    }
}
