/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as dom from '../../../../base/browser/dom.js';
import { Codicon } from '../../../../base/common/codicons.js';
import { ThemeIcon } from '../../../../base/common/themables.js';
import * as nls from '../../../../nls.js';
import { IConfigurationService } from '../../../../platform/configuration/common/configuration.js';
import { IContextKeyService } from '../../../../platform/contextkey/common/contextkey.js';
import { IContextMenuService } from '../../../../platform/contextview/browser/contextView.js';
import { IInstantiationService } from '../../../../platform/instantiation/common/instantiation.js';
import { IKeybindingService } from '../../../../platform/keybinding/common/keybinding.js';
import { IOpenerService } from '../../../../platform/opener/common/opener.js';
import { IThemeService } from '../../../../platform/theme/common/themeService.js';
import { IHoverService } from '../../../../platform/hover/browser/hover.js';
import { IViewDescriptorService } from '../../../common/views.js';
import { IViewletViewOptions } from '../../../browser/parts/views/viewsViewlet.js';
import { ViewPane } from '../../../browser/parts/views/viewPane.js';

export class GuardRailsSecurityView extends ViewPane {

	static readonly ID = 'workbench.guardrails.securityView';

	constructor(
		options: IViewletViewOptions,
		@IThemeService themeService: IThemeService,
		@IViewDescriptorService viewDescriptorService: IViewDescriptorService,
		@IInstantiationService instantiationService: IInstantiationService,
		@IKeybindingService keybindingService: IKeybindingService,
		@IContextMenuService contextMenuService: IContextMenuService,
		@IConfigurationService configurationService: IConfigurationService,
		@IContextKeyService contextKeyService: IContextKeyService,
		@IOpenerService openerService: IOpenerService,
		@IHoverService hoverService: IHoverService,
	) {
		super(options, keybindingService, contextMenuService, configurationService, contextKeyService, viewDescriptorService, instantiationService, openerService, themeService, hoverService);
	}

	protected override renderBody(container: HTMLElement): void {
		super.renderBody(container);
		container.classList.add('guardrails-security-view');

		const hero = dom.append(container, dom.$('.guardrails-security-hero'));
		const icon = dom.append(hero, dom.$(`.guardrails-security-hero-icon.${ThemeIcon.asClassName(Codicon.shield)}`));
		icon.setAttribute('aria-hidden', 'true');
		dom.append(hero, dom.$('h2.guardrails-security-title', undefined, nls.localize('guardrails.title', "GuardRails Security")));
		dom.append(hero, dom.$('p.guardrails-security-summary', undefined, nls.localize('guardrails.summary', "Every capability is explicit, reviewable, and revocable.")));

		const status = dom.append(container, dom.$('.guardrails-security-status'));
		dom.append(status, dom.$('.guardrails-security-status-dot'));
		dom.append(status, dom.$('span', undefined, nls.localize('guardrails.kernelReady', "Security kernel ready")));

		const cards = dom.append(container, dom.$('.guardrails-security-cards'));
		this.renderCard(cards, nls.localize('guardrails.supervisorTitle', "Supervisor"), nls.localize('guardrails.supervisorBody', "Connection setup is pending. No extension, terminal, or agent is represented as sandboxed until this boundary is active."));
		this.renderCard(cards, nls.localize('guardrails.approvalsTitle', "Approvals"), nls.localize('guardrails.approvalsBody', "Exact-action approvals and revocation will appear here when brokered operations are available."));
		this.renderCard(cards, nls.localize('guardrails.activityTitle', "Activity"), nls.localize('guardrails.activityBody', "Audited file, process, network, credential, and agent operations will appear here without exposing secret values."));
	}

	private renderCard(parent: HTMLElement, title: string, body: string): void {
		const card = dom.append(parent, dom.$('.guardrails-security-card'));
		dom.append(card, dom.$('h3.guardrails-security-card-title', undefined, title));
		dom.append(card, dom.$('p.guardrails-security-card-body', undefined, body));
	}
}
