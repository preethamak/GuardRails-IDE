/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import './media/guardrailsSecurityView.css';
import { Codicon } from '../../../../base/common/codicons.js';
import * as nls from '../../../../nls.js';
import { SyncDescriptor } from '../../../../platform/instantiation/common/descriptors.js';
import { Registry } from '../../../../platform/registry/common/platform.js';
import { ViewPaneContainer } from '../../../browser/parts/views/viewPaneContainer.js';
import { Extensions as ViewExtensions, IViewContainersRegistry, IViewsRegistry, ViewContainer, ViewContainerLocation } from '../../../common/views.js';
import { GuardRailsSecurityView } from './guardrailsSecurityView.js';

const guardRailsViewContainer: ViewContainer = Registry.as<IViewContainersRegistry>(ViewExtensions.ViewContainersRegistry).registerViewContainer({
	id: 'workbench.view.guardrails',
	title: nls.localize2('guardrails', "GuardRails"),
	icon: Codicon.shield,
	ctorDescriptor: new SyncDescriptor(ViewPaneContainer, ['workbench.view.guardrails', { mergeViewWithContainerWhenSingleView: true }]),
	storageId: 'workbench.guardrails.views.state',
	alwaysUseContainerInfo: true,
	order: 2.5,
}, ViewContainerLocation.Sidebar);

Registry.as<IViewsRegistry>(ViewExtensions.ViewsRegistry).registerViews([{
	id: GuardRailsSecurityView.ID,
	name: nls.localize2('guardrailsSecurity', "Security Center"),
	containerIcon: Codicon.shield,
	ctorDescriptor: new SyncDescriptor(GuardRailsSecurityView),
	canMoveView: true,
	canToggleVisibility: true,
	focusCommand: { id: 'workbench.action.focusGuardRailsSecurity' },
}], guardRailsViewContainer);
