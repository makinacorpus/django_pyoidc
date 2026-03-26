#!/bin/bash
################################################################
# This script is the second part of the e2e run recorder
# (ci_run_e2e_tests.sh).
# If you simply want to run e2e tests locally run instead:
#     python3 run_e2e_tests.py
################################################################

display=$1
if [ -f e2e_tests_video.mp4 ]; then
  echo " * removing previous recording e2e_tests_video.mp4"
  rm -f "e2e_tests_video.mp4"
fi

echo " * launch run_e2e_tests.py in background"
python3 run_e2e_tests.py &
pid=$!

export DISPLAY=$display

echo " * Capture DISPLAY:42 via ffmpeg"
read -r -d '' CMD << EOC
ffmpeg -f x11grab 
  -video_size 1920x1080
  -i :$display
  -codec:v
  libx264
  -r 12 
  e2e_tests_video.mp4
EOC
# Launch ffmpeg in a tmux session so we can send a command
# to it later on
tmux new-session -d -s e2eRecording ${CMD}

echo " * waiting for end of tests (PID $pid)"
wait ${pid}
tests_exit_code=${?}
echo " * stop ffmpeg recording"
# send a "q - quit" message to ffmpeg, so it can close the recording
# nicely and ensure the mp4 will work
tmux send-keys -t e2eRecording q
# let ffmpeg finish
sleep 5

if [ ${tests_exit_code} -eq 0 ]; then
  echo " * Tests were OK.";
else
  echo " * ERRORS detected in Tests!";
fi
exit ${tests_exit_code}