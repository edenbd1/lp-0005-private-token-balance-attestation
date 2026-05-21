import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Skeleton UI for the LP-0005 Basecamp app.
// Production version delegates `prove`, `verify`, and Logos Delivery `send`/`recv`
// to the C++ AttestationBridge wired up by `src/plugin.cpp`. Here the bindings
// are stubbed so the QML compiles standalone for layout review.
ApplicationWindow {
    visible: true
    width: 640
    height: 480
    title: "LP-0005 — Private balance attestation"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 12

        Label {
            text: "Prove balance ≥ N (LP-0005)"
            font.pixelSize: 22
        }

        TextField {
            id: contextField
            placeholderText: "context_id (e.g. \"chat-room-vip\")"
            Layout.fillWidth: true
        }
        TextField {
            id: thresholdField
            placeholderText: "threshold N (u128)"
            Layout.fillWidth: true
        }

        RowLayout {
            Button {
                text: "Prove"
                onClicked: bridge.prove(contextField.text, parseInt(thresholdField.text))
            }
            Button {
                text: "Send via Delivery"
                enabled: bridge.lastCredentialReady
                onClicked: bridge.send(contextField.text)
            }
        }

        Label {
            id: statusLine
            text: bridge.status
            Layout.fillWidth: true
            wrapMode: Text.Wrap
        }
    }
}
