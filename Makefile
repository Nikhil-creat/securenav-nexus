.PHONY: keys up down test attack export
keys:    ; ./scripts/setup_sros2.sh
up:      keys ; docker compose up --build -d
down:    ; docker compose down
test:    ; pytest -q
export:  ; docker compose run --rm vision-perception-node python3 -m vision.vision_node --export --precision fp16
attack:  ; ./sim/run_attack_suite.sh
