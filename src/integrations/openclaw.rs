use std::path::PathBuf;

pub fn setup(host: &str, port: u16, model: &str) {
    let provider_name = "anthropic-secured";
    let base_url = format!("http://{}:{}/anthropic", host, port);
    let model_id = format!("{}/{}", provider_name, model);

    println!("Configuring OpenClaw to use security proxy at {}", base_url);
    println!();

    let provider_json = format!(
        r#"{{"baseUrl":"{}","api":"anthropic-messages","models":[{{"id":"{}","name":"Claude (secured)"}}]}}"#,
        base_url, model
    );
    run_cmd(&[
        "config", "set",
        &format!("models.providers.{}", provider_name),
        &provider_json,
    ]);

    run_cmd(&[
        "config", "set",
        "agents.defaults.model.primary",
        &model_id,
    ]);

    copy_auth_profile(provider_name);

    let result = run_cmd_result(&[
        "config", "set",
        "plugins.entries.parallax-security.enabled",
        "false",
    ]);
    if result.is_err() {
        println!("  NOTE: Could not disable server-mode integration — if it's loaded, events may be double-counted.");
    }

    println!();
    println!("Done. OpenClaw will now route all Anthropic API traffic through the proxy.");
    println!("  Provider:  {}", provider_name);
    println!("  Model:     {}", model_id);
    println!("  Proxy URL: {}", base_url);
    println!();
    println!("Start the proxy with:");
    println!("  parallax serve --mode proxy -c <config.yaml>");
}

pub fn revert(model: &str) {
    let model_id = format!("anthropic/{}", model);

    println!("Reverting OpenClaw to use Anthropic directly");
    println!();

    run_cmd(&[
        "config", "set",
        "agents.defaults.model.primary",
        &model_id,
    ]);

    run_cmd(&[
        "config", "unset",
        "models.providers.anthropic-secured",
    ]);

    remove_auth_profile("anthropic-secured");

    run_cmd(&[
        "config", "set",
        "plugins.entries.parallax-security.enabled",
        "true",
    ]);

    println!();
    println!("Done. OpenClaw now uses {} directly.", model_id);
}

fn run_cmd(args: &[&str]) {
    let display: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    println!("  $ openclaw {}", display.join(" "));

    match std::process::Command::new("openclaw")
        .args(args)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("  ERROR: {}", stderr.trim());
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    println!("  {}", stdout.trim());
                }
            }
        }
        Err(e) => {
            eprintln!("  ERROR: Failed to run openclaw: {}", e);
        }
    }
}

fn run_cmd_result(args: &[&str]) -> Result<(), ()> {
    let display: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    println!("  $ openclaw {}", display.join(" "));

    match std::process::Command::new("openclaw")
        .args(args)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                Err(())
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    println!("  {}", stdout.trim());
                }
                Ok(())
            }
        }
        Err(_) => Err(()),
    }
}

fn copy_auth_profile(provider_name: &str) {
    let home = match dirs_home() {
        Some(h) => h,
        None => {
            println!("  WARNING: Could not determine home directory");
            return;
        }
    };

    let agents_dir = home.join(".openclaw").join("agents");
    if !agents_dir.is_dir() {
        println!("  WARNING: No agents directory found — you may need to configure auth manually.");
        return;
    }

    let mut copied = false;
    if let Ok(entries) = std::fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            let auth_file = entry.path().join("agent").join("auth-profiles.json");
            if !auth_file.exists() {
                continue;
            }

            match std::fs::read_to_string(&auth_file) {
                Ok(content) => {
                    let mut data: serde_json::Value = match serde_json::from_str(&content) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let profiles = match data.get_mut("profiles").and_then(|p| p.as_object_mut()) {
                        Some(p) => p,
                        None => continue,
                    };

                    let mut anthropic_key = None;
                    for (_id, profile) in profiles.iter() {
                        if profile.get("provider").and_then(|p| p.as_str()) == Some("anthropic") {
                            if let Some(key) = profile.get("key").and_then(|k| k.as_str()) {
                                anthropic_key = Some(key.to_string());
                                break;
                            }
                        }
                    }

                    let key = match anthropic_key {
                        Some(k) => k,
                        None => continue,
                    };

                    let new_profile_id = format!("{}:default", provider_name);
                    if profiles.contains_key(&new_profile_id) {
                        continue;
                    }

                    profiles.insert(
                        new_profile_id,
                        serde_json::json!({
                            "type": "api_key",
                            "provider": provider_name,
                            "key": key,
                        }),
                    );

                    if let Ok(json_str) = serde_json::to_string_pretty(&data) {
                        let _ = std::fs::write(&auth_file, format!("{}\n", json_str));
                        let agent_name = entry.file_name();
                        println!("  Copied Anthropic API key to {} in {}", provider_name, agent_name.to_string_lossy());
                        copied = true;
                    }
                }
                Err(_) => continue,
            }
        }
    }

    if !copied {
        println!("  WARNING: No Anthropic API key found to copy. Run: openclaw agents add <id>");
    }
}

fn remove_auth_profile(provider_name: &str) {
    let home = match dirs_home() {
        Some(h) => h,
        None => return,
    };

    let agents_dir = home.join(".openclaw").join("agents");
    if !agents_dir.is_dir() {
        return;
    }

    let profile_id = format!("{}:default", provider_name);
    if let Ok(entries) = std::fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            let auth_file = entry.path().join("agent").join("auth-profiles.json");
            if !auth_file.exists() {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&auth_file) {
                let mut data: serde_json::Value = match serde_json::from_str(&content) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let removed = data
                    .get_mut("profiles")
                    .and_then(|p| p.as_object_mut())
                    .map(|profiles| profiles.remove(&profile_id).is_some())
                    .unwrap_or(false);

                if removed {
                    if let Ok(json_str) = serde_json::to_string_pretty(&data) {
                        let _ = std::fs::write(&auth_file, format!("{}\n", json_str));
                        let agent_name = entry.file_name();
                        println!("  Removed {} auth from {}", provider_name, agent_name.to_string_lossy());
                    }
                }
            }
        }
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
}
