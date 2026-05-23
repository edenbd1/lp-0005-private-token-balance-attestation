// SPDX-License-Identifier: MIT OR Apache-2.0
//
// LP-0005 attestation plugin main pane.
//
// `bridge` is the AttestationBridge instance injected as a context property
// by plugin.cpp. It shells out to the local `attest` CLI to prove + verify.
// The Logos Delivery integration is feature-gated and tracked in whats-left.md.

import QtQuick 6
import QtQuick.Controls 6
import QtQuick.Layouts 6

Rectangle {
    id: root
    color: "#0d1117"
    anchors.fill: parent

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 16

        Label {
            text: "Private Balance Attestation"
            color: "#f0f6fc"
            font.pixelSize: 24
            font.bold: true
        }

        Label {
            text: "Prove a shielded token balance ≥ N without revealing npk, balance, or account id (LP-0005)."
            color: "#8b949e"
            font.pixelSize: 13
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }

        TextField {
            id: contextField
            placeholderText: "context_id (e.g. \"chat-room-vip\")"
            Layout.fillWidth: true
            color: "#f0f6fc"
            background: Rectangle { color: "#161b22"; border.color: "#30363d"; radius: 4 }
        }

        TextField {
            id: thresholdField
            placeholderText: "threshold N (e.g. 100000)"
            Layout.fillWidth: true
            color: "#f0f6fc"
            background: Rectangle { color: "#161b22"; border.color: "#30363d"; radius: 4 }
        }

        RowLayout {
            spacing: 12
            Button {
                text: "Prove"
                onClicked: bridge.prove(contextField.text, parseInt(thresholdField.text))
            }
            Button {
                text: "Send via Logos Delivery"
                enabled: bridge.lastCredentialReady
                onClicked: bridge.send(contextField.text)
            }
        }

        Rectangle {
            color: "#161b22"
            border.color: "#30363d"
            radius: 4
            Layout.fillWidth: true
            Layout.preferredHeight: 80
            Label {
                anchors.fill: parent
                anchors.margins: 12
                text: "status: " + bridge.status
                color: "#f0f6fc"
                wrapMode: Text.Wrap
                verticalAlignment: Text.AlignTop
            }
        }

        Item { Layout.fillHeight: true }
    }
}
