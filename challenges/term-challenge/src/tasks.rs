use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::types::{Difficulty, TaskDefinition};

fn task(
    id: &str,
    name: &str,
    instruction: &str,
    difficulty: Difficulty,
    timeout_secs: u64,
    docker_image: &str,
    test_script: &str,
) -> TaskDefinition {
    TaskDefinition {
        id: String::from(id),
        name: String::from(name),
        instruction: String::from(instruction),
        difficulty,
        timeout_secs,
        docker_image: String::from(docker_image),
        test_script: String::from(test_script),
    }
}

pub fn builtin_tasks() -> Vec<TaskDefinition> {
    vec![
        task(
            "create-file",
            "Create a File",
            "Create a file called /app/hello.txt containing the text 'Hello, World!'",
            Difficulty::Easy,
            60,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/hello.txt && grep -q 'Hello, World!' /app/hello.txt",
        ),
        task(
            "list-processes",
            "List Running Processes",
            "Write the output of `ps aux` to /app/processes.txt",
            Difficulty::Easy,
            60,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/processes.txt && [ -s /app/processes.txt ]",
        ),
        task(
            "find-largest-file",
            "Find Largest File",
            "Find the largest file in /var/log and write its name to /app/largest.txt",
            Difficulty::Medium,
            120,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/largest.txt && [ -s /app/largest.txt ]",
        ),
        task(
            "setup-nginx",
            "Setup Nginx Config",
            "Install nginx and configure it to serve static files from /var/www/html on port 8080. \
             Create an index.html with 'Welcome' as content.",
            Difficulty::Medium,
            180,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /var/www/html/index.html && grep -q 'Welcome' /var/www/html/index.html",
        ),
        task(
            "parse-json-log",
            "Parse JSON Logs",
            "Parse the JSON log file at /app/input.log, extract all entries with level 'ERROR', \
             and write them to /app/errors.json as a JSON array.",
            Difficulty::Medium,
            120,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/errors.json && python3 -c \"import json; d=json.load(open('/app/errors.json')); assert isinstance(d, list)\"",
        ),
        task(
            "create-user",
            "Create System User",
            "Create a new system user called 'appuser' with home directory /home/appuser and bash as default shell.",
            Difficulty::Easy,
            60,
            "ubuntu:22.04",
            "#!/bin/bash\nid appuser && [ -d /home/appuser ] && getent passwd appuser | grep -q '/bin/bash'",
        ),
        task(
            "compress-directory",
            "Compress Directory",
            "Create a tar.gz archive of /app/data directory and save it as /app/data.tar.gz. \
             The archive must preserve directory structure.",
            Difficulty::Easy,
            60,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/data.tar.gz && tar tzf /app/data.tar.gz | head -1",
        ),
        task(
            "setup-cron",
            "Setup Cron Job",
            "Create a cron job that runs '/usr/local/bin/cleanup.sh' every day at 3:00 AM as root. \
             Write the crontab entry to /app/crontab.txt as well.",
            Difficulty::Medium,
            120,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/crontab.txt && grep -q '0 3' /app/crontab.txt && grep -q 'cleanup.sh' /app/crontab.txt",
        ),
        task(
            "docker-compose",
            "Write Docker Compose",
            "Write a docker-compose.yml at /app/docker-compose.yml that defines two services: \
             'web' using nginx:latest on port 80 and 'db' using postgres:15 with POSTGRES_PASSWORD=secret.",
            Difficulty::Hard,
            180,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/docker-compose.yml && grep -q 'nginx' /app/docker-compose.yml && grep -q 'postgres' /app/docker-compose.yml",
        ),
        task(
            "iptables-rule",
            "Configure Firewall Rule",
            "Write an iptables rule set to /app/rules.sh that blocks all incoming traffic on port 22 \
             except from 10.0.0.0/8, and allows all outgoing traffic.",
            Difficulty::Hard,
            180,
            "ubuntu:22.04",
            "#!/bin/bash\ntest -f /app/rules.sh && grep -q 'iptables' /app/rules.sh && grep -q '10.0.0.0' /app/rules.sh",
        ),
    ]
}

pub fn select_tasks(seed: u64, count: usize) -> Vec<TaskDefinition> {
    let all = builtin_tasks();
    if count >= all.len() {
        return all;
    }
    let mut indices: Vec<usize> = (0..all.len()).collect();
    let mut rng = seed;
    for i in (1..indices.len()).rev() {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (rng >> 33) as usize % (i + 1);
        indices.swap(i, j);
    }
    indices
        .into_iter()
        .take(count)
        .map(|i| all[i].clone())
        .collect()
}
