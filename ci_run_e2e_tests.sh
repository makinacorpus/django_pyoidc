#!/bin/bash
################################################################
# This script will start the e2e tests while capturing logs and
# making a video record.
# This is aimed for CI runs.
# If you simply want to run e2e tests locally run instead:
#     python3 run_e2e_tests.py
# Using this recording entrypoint requires:
# - tee
# - ffmpeg
# - xvfb
# - tmux
################################################################
set -o pipefail
echo " * Start tests/e2e/record_e2e_tests.sh in DISPLAY:42 via xvfb-run"
 
# export DISPLAY=:42
xvfb-run \
  --listen-tcp \
  --server-num 42 \
  --auth-file /tmp/xvfb.auth \
  -s "-ac -screen 0 1920x1080x24" \
  ./tests/e2e/record_e2e_tests.sh 42 | tee -a e2e_tests.log
tests_exit_code=${?}
echo " * End of run_e2e_tests"
exit ${tests_exit_code}
