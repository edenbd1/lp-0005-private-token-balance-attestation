// SPDX-License-Identifier: MIT OR Apache-2.0
//
// AttestationBridge: drives the local `attest` CLI as a child process and
// surfaces results to the QML status panel. Owns a per-session artefacts
// directory under XDG_CACHE_HOME.
//
// Why not link the SDK directly? The SDK depends on risc0-zkvm which pulls a
// large transitive graph into the plugin DSO; shelling out keeps the plugin
// lean and lets the Rust side iterate without rebuilding the Basecamp app.

#include "attestation_bridge.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>

AttestationBridge::AttestationBridge(QObject *parent) : QObject(parent) {
    const QString cacheBase = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    m_artefactsDir = cacheBase + QStringLiteral("/lp-0005");
    QDir().mkpath(m_artefactsDir);
    m_status = QStringLiteral("ready — artefacts at %1").arg(m_artefactsDir);
}

void AttestationBridge::prove(const QString &context, qulonglong threshold) {
    if (context.isEmpty()) {
        m_status = QStringLiteral("prove: context is empty");
        emit statusChanged();
        return;
    }
    const QString attest = findAttest();
    if (attest.isEmpty()) {
        m_status = QStringLiteral(
            "prove: cannot locate the `attest` binary. Set ATTEST_BIN or place it next to the plugin.");
        emit statusChanged();
        return;
    }

    const QString presenterPath = m_artefactsDir + QStringLiteral("/presenter.json");
    const QString credentialPath = m_artefactsDir + QStringLiteral("/credential.bin");

    // 1. keygen if no presenter key exists.
    if (!QFile::exists(presenterPath)) {
        QProcess kg;
        kg.start(attest, {QStringLiteral("keygen"),
                          QStringLiteral("--out"), presenterPath});
        kg.waitForFinished(10000);
        if (kg.exitCode() != 0) {
            m_status = QStringLiteral("prove: keygen failed (%1): %2")
                           .arg(kg.exitCode())
                           .arg(QString::fromUtf8(kg.readAllStandardError()));
            emit statusChanged();
            return;
        }
    }

    // 2. prove.
    m_status = QStringLiteral("proving (RISC0_DEV_MODE=0)... ~7 s");
    emit statusChanged();
    QProcess pv;
    auto env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("RISC0_DEV_MODE"), QStringLiteral("0"));
    pv.setProcessEnvironment(env);
    pv.start(attest, {
        QStringLiteral("prove"),
        QStringLiteral("--presenter"), presenterPath,
        QStringLiteral("--balance"),   QStringLiteral("1000000"),
        QStringLiteral("--threshold"), QString::number(threshold),
        QStringLiteral("--context"),   context,
        QStringLiteral("--out"),       credentialPath,
    });
    pv.waitForFinished(60000);
    if (pv.exitCode() != 0) {
        m_status = QStringLiteral("prove: failed (%1): %2")
                       .arg(pv.exitCode())
                       .arg(QString::fromUtf8(pv.readAllStandardError()));
        emit statusChanged();
        return;
    }

    m_credentialPath  = credentialPath;
    m_credentialReady = true;
    QFileInfo cf(credentialPath);
    m_status = QStringLiteral("proved — credential ready (%1 KB) at %2")
                   .arg(cf.size() / 1024)
                   .arg(credentialPath);
    emit statusChanged();
}

void AttestationBridge::send(const QString &topic) {
    if (!m_credentialReady) {
        m_status = QStringLiteral("send: no credential — run prove first");
        emit statusChanged();
        return;
    }
    // Logos Delivery binding is feature-gated (qt_bridge). Until the production
    // Qt helper ships, we record the publish intent. See docs/whats-left.md #2.
    m_status = QStringLiteral(
                   "send (stub): would publish credential at %1 to Logos Delivery "
                   "topic '%2'. Real binding tracked in whats-left.md #2.")
                   .arg(m_credentialPath)
                   .arg(topic);
    emit statusChanged();
}

QString AttestationBridge::findAttest() {
    const QByteArray override_ = qgetenv("ATTEST_BIN");
    if (!override_.isEmpty() && QFile::exists(QString::fromUtf8(override_))) {
        return QString::fromUtf8(override_);
    }
    const QString sidecar = QCoreApplication::applicationDirPath()
                            + QStringLiteral("/attest");
    if (QFile::exists(sidecar)) {
        return sidecar;
    }
    // Dev fallback: cargo target dir.
    const QString devPath = QCoreApplication::applicationDirPath()
                            + QStringLiteral("/../../../target/release/attest");
    QFileInfo fi(devPath);
    if (fi.exists()) {
        return fi.canonicalFilePath();
    }
    return {};
}
