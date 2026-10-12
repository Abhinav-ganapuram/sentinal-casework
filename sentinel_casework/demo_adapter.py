"""Scripted investigation decisions for offline demonstrations."""


class DemoDecider:
    def __call__(self, context: dict) -> dict:
        finding = context["finding"]
        completed_tools = {
            observation["tool"]
            for observation in context["observations"]
        }

        if "get_user_events" not in completed_tools:
            return {
                "tool": "get_user_events",
                "value": finding["user"],
                "reason": "Demo plan: review activity for the affected user.",
            }

        if "get_ip_events" not in completed_tools:
            return {
                "tool": "get_ip_events",
                "value": finding["source_ip"],
                "reason": "Demo plan: review activity from the source IP.",
            }

        return {
            "tool": "finish",
            "value": "",
            "reason": (
                "Scripted demo completed user and IP lookups. "
                "The collected evidence requires human review."
            ),
        }