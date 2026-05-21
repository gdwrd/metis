#!/usr/bin/env bash

run_command() {
  cmd="$1"
  sh -c "$cmd"
}

run_safe_command() {
  cmd="$(validate "$1")"
  sh -c "$cmd"
}
