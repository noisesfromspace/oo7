import QtQuick
import qs.Common
import qs.Modules.Plugins
import qs.Services
import qs.Widgets

PluginComponent {
    id: root

    pluginId: "keyringStatus"
    pluginService: PluginService

    property bool unlocked: false

    function refresh() {
        Proc.runCommand(
            "keyringStatus.status",
            ["systemctl", "--user", "is-active", "oo7-daemon"],
            (out, code) => {
                root.unlocked = (code === 0 && out.trim() === "active");
            }
        );
    }

    Timer {
        interval: 5000
        running: true
        repeat: true
        onTriggered: root.refresh()
    }

    Component.onCompleted: root.refresh()

    pillClickAction: () => {
        Proc.runCommand(
            "keyringStatus.restart",
            ["systemctl", "--user", "restart", "oo7-daemon"],
            () => {}
        );
    }

    horizontalBarPill: Component {
        DankIcon {
            name: root.unlocked ? "lock_open" : "lock"
            size: root.iconSize
            color: root.unlocked ? Theme.primary : Theme.widgetIconColor
        }
    }

    verticalBarPill: Component {
        DankIcon {
            name: root.unlocked ? "lock_open" : "lock"
            size: root.iconSize
            color: root.unlocked ? Theme.primary : Theme.widgetIconColor
        }
    }
}
