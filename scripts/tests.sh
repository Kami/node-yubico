if [ ! $TEST_FILES ]; then
  TEST_FILES=$(find tests/ -type f -name "test-*.js" -print0 | tr "\0" " " | sed '$s/.$//')
fi

NODE_PATH=lib node_modules/whiskey/bin/whiskey \
  --tests "${TEST_FILES}" \
  --real-time --sequential
