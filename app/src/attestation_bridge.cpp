// Skeleton implementation — not yet wired up.
// Production version executes ./attest as a child process and reads the
// resulting credential file. For now we expose a stub to keep the QML happy
// during layout work.

#include "attestation_bridge.h"

AttestationBridge::AttestationBridge(QObject *parent) : QObject(parent) {
    m_status = "ready";
}

void AttestationBridge::prove(const QString &context, qulonglong threshold) {
    m_status = QString("[stub] prove(%1, %2): not yet wired to ./attest").arg(context).arg(threshold);
    m_credentialReady = false;
    emit statusChanged();
}

void AttestationBridge::send(const QString &topic) {
    m_status = QString("[stub] send(%1): not yet wired to logos-delivery-module").arg(topic);
    emit statusChanged();
}
