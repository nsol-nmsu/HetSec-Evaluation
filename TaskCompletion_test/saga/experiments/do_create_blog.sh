#!/usr/bin/env bash
for i in {1..9}; do
    echo "=== run $i ==="
    python schedule_meeting_MABE.py query ../user_configs/bob.yaml ../user_configs/emma.yaml
    sleep 60
done