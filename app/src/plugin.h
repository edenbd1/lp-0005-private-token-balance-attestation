// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Top-level Qt plugin object — owns the QQuickWidget that hosts the
// QML scene and exposes the AttestationBridge to it as a context
// property.

#pragma once

#include <QObject>
#include <QString>
#include <QWidget>

// LogosAPI is forward-declared rather than included here so this header
// builds standalone in the IDE-only preview-app path.
class LogosAPI;
class AttestationBridge;

// Basecamp's IComponent interface, declared here so the manual build
// path doesn't need the SDK header on the include path.
class IComponent {
public:
    virtual ~IComponent() = default;
    virtual QString name() const = 0;
    virtual QWidget* createWidget(LogosAPI* api) = 0;
    virtual void destroyWidget(QWidget* widget) = 0;
};

// IID required by Q_INTERFACES so moc can build the metadata table.
Q_DECLARE_INTERFACE(IComponent, "com.networkschool.logos.IComponent/1.0")

#define AttestationPlugin_IID "com.networkschool.lp0005.AttestationPlugin/1.0"

class AttestationPlugin : public QObject, public IComponent {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID AttestationPlugin_IID FILE "metadata.json")
    Q_INTERFACES(IComponent)

public:
    explicit AttestationPlugin(QObject* parent = nullptr);
    ~AttestationPlugin() override;

    // IComponent
    QString  name() const override { return QStringLiteral("lp_0005_attestation"); }
    QWidget* createWidget(LogosAPI* api) override;
    void     destroyWidget(QWidget* widget) override;

private:
    AttestationBridge* m_bridge = nullptr;
};
