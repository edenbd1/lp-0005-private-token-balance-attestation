// SPDX-License-Identifier: MIT OR Apache-2.0
#include "plugin.h"
#include "attestation_bridge.h"

#include <QQmlContext>
#include <QQmlEngine>
#include <QQuickWidget>
#include <QUrl>

AttestationPlugin::AttestationPlugin(QObject* parent) : QObject(parent) {}

AttestationPlugin::~AttestationPlugin() = default;

QWidget* AttestationPlugin::createWidget(LogosAPI* /*api*/) {
    // We don't (yet) use LogosAPI for storage/delivery — the bridge talks to
    // the local `attest` CLI. Logos Delivery integration is feature-gated and
    // tracked in docs/whats-left.md.
    m_bridge = new AttestationBridge(this);

    auto* view = new QQuickWidget();
    view->engine()->rootContext()->setContextProperty(
        QStringLiteral("bridge"), m_bridge);
    view->setResizeMode(QQuickWidget::SizeRootObjectToView);
    view->setSource(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    return view;
}

void AttestationPlugin::destroyWidget(QWidget* widget) {
    if (widget) {
        widget->deleteLater();
    }
}
