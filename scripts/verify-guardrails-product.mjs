import { readFileSync } from 'node:fs';

const product = JSON.parse(readFileSync(new URL('../product.json', import.meta.url)));
const expected = {
	nameShort: 'GuardRails IDE',
	nameLong: 'GuardRails IDE',
	applicationName: 'guardrails-ide',
	dataFolderName: '.guardrails-ide',
	win32AppUserModelId: 'io.guardrails.ide',
	darwinBundleIdentifier: 'io.guardrails.ide',
	linuxIconName: 'guardrails-ide',
	urlProtocol: 'guardrails-ide',
};

for (const [key, value] of Object.entries(expected)) {
	if (product[key] !== value) throw new Error(`product.json ${key} must be ${JSON.stringify(value)}`);
}

for (const key of ['extensionsGallery', 'extensionsGalleryUrl', 'extensionGallery']) {
	if (key in product) throw new Error(`public extension marketplace configuration must remain disabled: ${key}`);
}

const source = readFileSync(new URL('../docs/architecture/upstream-code-oss.md', import.meta.url), 'utf8');
if (!source.includes('df53daabb18cd157bdb08c7f01c34df936cf12f4')) throw new Error('upstream pin is missing');

console.log('GuardRails product configuration verified.');
