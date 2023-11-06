#!/bin/bash

printf "%-10s %-10s %-20s %-50s\n" "USER" "PID" "DOCKER NAME" "COMMAND"
while IFS= read -r container_id; do
    docker_name=$(docker inspect --format '{{ .Name }}' "$container_id" | sed 's/^\///')
    docker_top_output=$(docker top $container_id axo user,pid,command)
    docker_top_output=$(echo "$docker_top_output" | tail -n +2)
    while IFS= read -r line; do
        user=$(echo $line | awk '{print $1}')
        pid=$(echo $line | awk '{print $2}')
        command=$(echo $line | cut -d ' ' -f3-)
        printf "%-10s %-10s %-20s %-50s\n" "$user" "$pid" "$docker_name" "$command"
    done <<< "$docker_top_output"

done <<< "$(docker ps -q)"

