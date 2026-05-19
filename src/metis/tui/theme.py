# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

METIS_CSS = """
App {
    background: ansi_default;
    color: ansi_default;
}

Screen {
    background: ansi_default;
    color: #a5a5a5;
}

#shell {
    height: 100%;
    width: 100%;
    background: transparent;
}

#hero {
    height: auto;
    padding: 1 2 0 2;
    background: transparent;
    border: none;
}

#top {
    height: auto;
    color: #9b4dff;
    text-style: bold;
}

#startup {
    width: 64;
    height: auto;
    margin-top: 0;
    padding: 0;
    color: #a66cff;
    background: transparent;
}

#connection-status {
    height: 1;
    margin-top: 1;
    color: #b9b9b9;
    background: transparent;
}

#tagline {
    height: 2;
    color: #8f47ff;
    background: transparent;
    margin-top: 1;
}

#workspace {
    height: 1fr;
    padding: 1 2 0 2;
    background: transparent;
}

#activity {
    width: 100%;
    height: 1;
    padding: 0;
    background: transparent;
    border: none;
    color: #9b4dff;
}

#command-completions {
    width: 100%;
    max-height: 8;
    margin: 0 0 1 0;
    padding: 0 1;
    background: transparent;
    color: #d8d8d8;
    border: tall #262626;
}

#transcript {
    height: 1fr;
    background: transparent;
    border: none;
    padding: 0 1;
    color: #a5a5a5;
}

#tool-log {
    height: 8;
    min-height: 5;
    max-height: 10;
    margin-top: 1;
    padding: 0 1;
    background: transparent;
    color: #a5a5a5;
    border: tall #222222;
}

#status {
    height: 1;
    background: transparent;
    color: #8ee6a5;
    padding: 0;
}

#bottom-panel {
    height: auto;
    padding: 0 2;
    background: transparent;
}

#input {
    width: 1fr;
    height: 2;
    margin: 1 0;
    padding: 0 1;
    background: transparent;
    color: #f5f5f5;
    border: none;
}

#shortcuts {
    height: 1;
    padding: 0 2;
    background: transparent;
    color: #8c8c8c;
}
"""


def metis_logo(width: int = 80) -> str:
    if width < 72:
        return "\n".join(
            (
                "    _    ____  __  __",
                "   / \\  |  _ \\|  \\/  |",
                "  / _ \\ | |_) | |\\/| |",
                " / ___ \\|  _ <| |  | |",
                "/_/   \\_\\_| \\_\\_|  |_|",
                "ARM METIS",
            )
        )
    return "\n".join(
        (
            "    _    ____  __  __      __  __ _____ _____ ___ ____",
            "   / \\  |  _ \\|  \\/  |    |  \\/  | ____|_   _|_ _/ ___|",
            "  / _ \\ | |_) | |\\/| |    | |\\/| |  _|   | |  | |\\___ \\",
            " / ___ \\|  _ <| |  | |    | |  | | |___  | |  | | ___) |",
            "/_/   \\_\\_| \\_\\_|  |_|    |_|  |_|_____| |_| |___|____/",
            "ARM METIS",
        )
    )
