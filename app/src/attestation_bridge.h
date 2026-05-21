// LP-0005 Basecamp app — C++ bridge between the QML UI and the Rust SDK.
//
// Implementation lives in `attestation_bridge.cpp` and shells out to the
// `attest` CLI (release build) until the FFI binding lands. The CLI write-side
// produces a credential file; the bridge then exposes it to QML and (optionally)
// hands it to `logos-delivery-module`.

#pragma once

#include <QObject>
#include <QString>

class AttestationBridge : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(bool lastCredentialReady READ lastCredentialReady NOTIFY statusChanged)

public:
    explicit AttestationBridge(QObject *parent = nullptr);

    QString status() const { return m_status; }
    bool lastCredentialReady() const { return m_credentialReady; }

public slots:
    void prove(const QString &context, qulonglong threshold);
    void send(const QString &topic);

signals:
    void statusChanged();

private:
    QString m_status;
    bool m_credentialReady = false;
    QString m_credentialPath;
};
