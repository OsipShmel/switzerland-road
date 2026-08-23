from vls import VLS, VLSStatus, InstrumentReport


def main() -> None:
    report = InstrumentReport(executor_name="dast001", action_taken="proverena popa", result_details="da ne vrode ne bolit")

    v = VLS(
        id="popa",
        title="bolit",
        status=VLSStatus.UNCHECKED,
        verification_history={
            "dast": {"run_executed": False, "verdict_output": "not_tested", "report": report},
            "pentest": {"run_executed": False, "verdict_output": "not_tested"},
        },
    )
    print(v.model_dump_json(indent=2))