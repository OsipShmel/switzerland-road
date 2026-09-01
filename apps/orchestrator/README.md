пока что запускает только саст, делает vls

## по дефолту ищет sqli 
uv run --package orchestrator orchestrator \
  --target-dir target \
  --semgrep-config p/default \
  --output output/pipeline-result.json