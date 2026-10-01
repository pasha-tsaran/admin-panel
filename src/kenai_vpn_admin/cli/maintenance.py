from __future__ import annotations

import argparse

from kenai_vpn_admin.main import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Kenai control-plane maintenance")
    parser.add_argument("operation", choices=("collect-metrics", "send-notifications"))
    args = parser.parse_args()
    app = create_app()
    try:
        with app.state.session_factory() as db:
            if args.operation == "collect-metrics":
                app.state.console_service.collect_metrics(db)
            else:
                app.state.console_service.send_pending_notifications(db)
            db.commit()
    finally:
        app.state.engine.dispose()


if __name__ == "__main__":
    main()
