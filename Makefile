.PHONY: keys up down observe test lint plan train export attack k8s
keys:    ; ./scripts/setup_sros2.sh
up:      keys ; docker compose up --build -d
observe: ; docker compose --profile observability up -d
down:    ; docker compose down
test:    ; pytest -q
lint:    ; flake8 src sim scripts tests --max-line-length 170 --extend-ignore E203,W503
plan:    ; PYTHONPATH=src python3 -m nexusctl plan "go to (25,4) then north 6 m"
train:   ; docker compose run --rm vision-perception-node python3 -m vision.train_vision --epochs 5 --export
export:  ; docker compose run --rm vision-perception-node python3 -m vision.vision_node --export --precision fp16
attack:  ; ./sim/run_attack_suite.sh
k8s:     ; kubectl apply -f deploy/k8s/nexus.yaml
