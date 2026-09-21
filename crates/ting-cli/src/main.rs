use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use ting_client::*;
fn a(name: &'static str) -> Arg {
    Arg::new(name).long(name).value_name(name.to_uppercase())
}
fn flag(name: &'static str) -> Arg {
    a(name).action(ArgAction::SetTrue)
}
fn arg(name: &'static str) -> Arg {
    Arg::new(name)
}
fn command(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about).after_help("Global options: --org ORG --api-url ORIGIN --json\nSee also: ting docs, ting COMMAND --help")
}
fn group(name: &'static str, about: &'static str) -> Command {
    command(name, about)
        .subcommand_required(true)
        .arg_required_else_help(true)
}
fn page(c: Command) -> Command {
    c.arg(a("limit").value_parser(clap::value_parser!(u64).range(1..=100)))
        .arg(a("cursor"))
}
fn app(c: Command) -> Command {
    c.arg(a("app"))
}
fn filters(c: Command) -> Command {
    app(c)
        .arg(a("type"))
        .arg(a("read").value_parser(["true", "false"]))
}
fn proof(c: Command, obo: bool) -> Command {
    let c = c
        .arg(a("write-request").conflicts_with_all([
            "request-file",
            "proof-token-stdin",
            "proof-token-file",
        ]))
        .arg(a("request-file"))
        .arg(flag("proof-token-stdin").conflicts_with("proof-token-file"))
        .arg(a("proof-token-file"));
    if obo {
        c.arg(flag("obo-stdin").conflicts_with_all([
            "obo-file",
            "write-request",
            "proof-token-stdin",
            "proof-token-file",
        ]))
        .arg(a("obo-file").conflicts_with_all([
            "write-request",
            "proof-token-stdin",
            "proof-token-file",
        ]))
    } else {
        c
    }
}
fn prefs(c: Command) -> Command {
    app(c)
        .arg(a("service").conflicts_with("type"))
        .arg(a("type"))
}
fn cli() -> Command {
    Command::new("ting").about("Durable notifications for carbons and silicons.").disable_version_flag(true)
 .arg(flag("json").global(true)).arg(a("org").global(true)).arg(a("api-url").global(true)).arg(flag("version").global(true))
 .after_help("Receive: ting login --token-stdin → ting org use tos → ting webhook http://localhost:8080/ting\nSend: ting send --type 'tos>dm.msg.received' --for ID --key KEY --data '{}' --write-request send.json\nThen obtain an IAM App Proof Token and run: ting send --request-file send.json --proof-token-stdin\nAll commands support --help. Documentation: ting docs")
 .subcommand(command("iam","Show Ting application information"))
 .subcommand(command("docs","Read bundled documentation offline").arg(a("topic").value_parser(["usage","development"]).default_value("usage")))
 .subcommand(command("login","Exchange an IAM short-lived login token; never a password").arg(arg("token").conflicts_with("token-stdin")).arg(flag("token-stdin")).subcommand(command("status","Check this profile's saved session")))
 .subcommand(command("logout","Revoke this profile's session and stop its local forwarding"))
 .subcommand(group("org","Choose an IAM organisation").subcommand(page(command("list","List accessible organisations"))).subcommand(command("current","Show effective organisation and selection source")).subcommand(command("use","Validate and save an organisation").arg(arg("id").required(true))))
 .subcommand(group("apps","Inspect visible Honeycomb applications").subcommand(page(command("list","List visible applications"))))
 .subcommand(group("types","Manage application notification types").subcommand(page(app(command("list","List application types")).mut_arg("app",|a|a.required(true)))).subcommand(command("register","Register a notification type").arg(a("type").required(true)).arg(a("description").required(true))).subcommand(command("update","Update a type description").arg(a("type").required(true)).arg(a("description").required(true))))
 .subcommand(group("subscriptions","Manage permission to receive from an application").subcommand(proof(app(command("register","Prepare or execute an OBO subscription registration")).arg(a("for")),true)).subcommand(proof(page(app(command("list","List recipient grants or prepare an app query")).arg(a("for"))),false)).subcommand(proof(command("revoke","Revoke a grant as recipient or proof-authorized app").arg(arg("id")),false)))
 .subcommand(proof(command("send","Prepare or submit one proof-bound notification").arg(a("type")).arg(a("for")).arg(a("key")).arg(a("data")).arg(a("metadata")).arg(a("transport").value_parser(["http","websocket"]).default_value("http")),false))
 .subcommand(group("sent","Inspect application sent history using fresh proofs").subcommand(proof(page(filters(command("list","Prepare or execute a sent query")).arg(a("for"))),false)).subcommand(proof(app(command("get","Prepare or execute a full sent-record query")).arg(arg("id")).arg(a("deliveries-cursor")),false)))
 .subcommand(group("inbox","Read durable recipient notification history").subcommand(page(filters(command("list","List one page; reading output does not mark it read")).arg(flag("silent").conflicts_with("all")).arg(flag("all")))).subcommand(command("get","Get a full ting without marking it read").arg(arg("id").required(true))).subcommand(command("mark-read","Mark explicitly viewed tings as read").arg(arg("ids").required(true).num_args(1..=100))))
 .subcommand(group("preferences","Control notification preferences").subcommand(page(prefs(command("list","List explicit overrides")))).subcommand(prefs(command("set","Set an app, service or event override")).mut_arg("app",|a|a.required(true)).arg(a("enabled").required(true).value_parser(["true","false"]))).subcommand(prefs(command("reset","Remove exactly one preference override")).mut_arg("app",|a|a.required(true))))
 .subcommand(command("webhook","Attach a local destination; URLs and secrets stay on this system").arg(arg("url")).arg(a("id")).arg(flag("secret-stdin").conflicts_with("clear-secret")).arg(flag("clear-secret").requires("id")).arg(a("health-url").conflicts_with("clear-health-url")).arg(flag("clear-health-url").requires("id")).arg(flag("takeover").requires("id")).subcommand(page(command("list","List registrations with this system's local destinations"))))
 .subcommand(command("unhook","Detach one destination while retaining its stable ID and pending history").arg(arg("id").required(true)))
 .subcommand(group("daemon","Inspect the one shared system receiver").subcommand(command("status","Report status without starting the service")).subcommand(command("reconnect","Resume this identity's attached or paused hooks in the selected org")))
 .subcommand(group("config","Manage private profile settings").subcommand(command("list","List settings")).subcommand(command("get","Get a setting").arg(arg("key").required(true))).subcommand(command("set","Set a setting").arg(arg("key").required(true)).arg(arg("value").required(true).value_parser(["true","false"]))))
 .subcommand(group("bug","Submit an explicit bug report").subcommand(command("report","Upload supplied report and attachments to Ting support storage").arg(a("title").required(true)).arg(a("body").conflicts_with("body-file")).arg(a("body-file")).arg(a("attach").action(ArgAction::Append)).arg(a("pr"))))
}
fn s<'a>(m: &'a ArgMatches, k: &str) -> Option<&'a str> {
    m.try_get_one::<String>(k)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn b(m: &ArgMatches, k: &str) -> bool {
    m.try_get_one::<bool>(k)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn required<'a>(m: &'a ArgMatches, k: &str) -> Result<&'a str> {
    let value = s(m, k).ok_or_else(|| Error::input(format!("{k} is required.")))?;
    if ["id", "app", "type", "for", "key", "url"].contains(&k) {
        nonempty(value, k)?;
    }
    Ok(value)
}

fn limit(m: &ArgMatches) -> u64 {
    m.try_get_one::<u64>("limit")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(50)
}
fn list_query(m: &ArgMatches, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut q = vec![("limit".into(), limit(m).to_string())];
    for (arg, field) in extra.iter().copied().chain([("cursor", "cursor")]) {
        if let Some(v) = s(m, arg) {
            q.push((field.into(), v.into()))
        }
    }
    q
}
fn selection(root: &ArgMatches, settings: &Settings) -> Result<Option<(String, &'static str)>> {
    let v = if let Some(o) = s(root, "org") {
        Some((o.to_owned(), "--org"))
    } else if let Ok(o) = std::env::var("SILICON_ORG") {
        Some((o, "SILICON_ORG"))
    } else {
        settings.org.clone().map(|o| (o, "saved"))
    };
    if let Some((v, _)) = &v {
        nonempty(v, "Org")?;
    }
    Ok(v)
}
fn selected<'a>(v: &'a Option<(String, &str)>) -> Result<&'a str> {
    v.as_ref()
        .map(|(s, _)| s.as_str())
        .ok_or_else(|| Error::input("Select an org with --org, SILICON_ORG or ting org use."))
}
fn origin(root: &ArgMatches) -> Result<String> {
    let raw=s(root,"api-url").map(str::to_owned).or_else(||std::env::var("TING_API_URL").ok()).or_else(||Some(option_env!("TING_API_URL").unwrap_or("https://backend.ting.teamofsilicons.com").to_owned())).ok_or_else(||Error::input("This development build has no published API origin. Supply --api-url or TING_API_URL."))?;
    api_origin(&raw)
}
async fn recipient(
    client: &Client,
    profile: &Profile,
    test: &TestHeaders,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let session = profile.session(&client.origin)?;
    client
        .json(method, path, body, Some(&session.token), test)
        .await
}
fn proof_mode(m: &ArgMatches) -> bool {
    ["write-request", "request-file", "proof-token-file"]
        .iter()
        .any(|k| s(m, k).is_some())
        || b(m, "proof-token-stdin")
}
async fn execute_proof(
    op: ProofOperation,
    m: &ArgMatches,
    root: &ArgMatches,
    org: Option<&str>,
) -> Result<Value> {
    let building = [
        "app",
        "type",
        "for",
        "key",
        "data",
        "metadata",
        "id",
        "read",
        "cursor",
        "deliveries-cursor",
    ];
    if let Some(file) = s(m, "request-file") {
        if building.iter().any(|k| s(m, k).is_some())
            || m.try_get_one::<u64>("limit").ok().flatten().is_some()
        {
            return Err(Error::input(
                "Request-file execution cannot include body-building flags or positional IDs.",
            ));
        }
        let obo = op == ProofOperation::Register;
        let stdin = b(
            m,
            if obo {
                "obo-stdin"
            } else {
                "proof-token-stdin"
            },
        );
        let file_secret = s(m, if obo { "obo-file" } else { "proof-token-file" });
        if stdin == file_secret.is_some() {
            return Err(Error::input(
                "Execution requires exactly one matching proof input.",
            ));
        }
        if obo && (b(m, "proof-token-stdin") || s(m, "proof-token-file").is_some()) {
            return Err(Error::input(
                "Subscription registration requires --obo-stdin or --obo-file.",
            ));
        }
        let p = Prepared::new(
            op,
            fs::read(file).map_err(|_| Error::input("Could not read request file."))?,
            org,
        )?;
        let proof = secret(file_secret)?;
        let test = TestHeaders::environment()?;
        let api = origin(root)?;
        if op == ProofOperation::Send && s(m, "transport") == Some("websocket") {
            start_service().await;
            return ipc(json!({"op":"send","api_url":api,"proof_token":proof,"body":String::from_utf8(p.body).map_err(|_|Error::input("Request must be UTF-8."))?,"headers":test})).await;
        }
        let mut result = p.execute(&Client::new(&api)?, &proof, &test).await?;
        if op == ProofOperation::SentList {
            if let Some(items) = result["items"].as_array_mut() {
                for item in items {
                    if let Some(o) = item.as_object_mut() {
                        o.remove("data");
                        o.remove("metadata");
                    }
                }
            }
        }
        return Ok(result);
    }
    if b(m, "proof-token-stdin")
        || s(m, "proof-token-file").is_some()
        || b(m, "obo-stdin")
        || s(m, "obo-file").is_some()
    {
        return Err(Error::input("Proof inputs require --request-file."));
    }
    let out = required(m, "write-request")?;
    let mut v = json!({"org_id":org.ok_or_else(||Error::input("Select an org before preparing a request."))?});
    let obj = v.as_object_mut().unwrap();
    for (arg, field) in [
        ("app", "app_id"),
        ("type", "type"),
        ("for", "for"),
        ("key", "key"),
        ("id", "id"),
        ("cursor", "cursor"),
        ("deliveries-cursor", "deliveries_cursor"),
    ] {
        if let Some(x) = s(m, arg) {
            obj.insert(field.into(), json!(x));
        }
    }
    if op == ProofOperation::Send {
        obj.insert("data".into(), object_argument(required(m, "data")?)?);
        obj.insert(
            "metadata".into(),
            object_argument(s(m, "metadata").unwrap_or("{}"))?,
        );
    }
    if [ProofOperation::Subscriptions, ProofOperation::SentList].contains(&op) {
        obj.insert("limit".into(), json!(limit(m)));
    }
    if let Some(read) = s(m, "read") {
        obj.insert("read".into(), json!(read == "true"));
    }
    Prepared::new(op, serde_json::to_vec(&v).unwrap(), org)?.write(Path::new(out))
}
async fn start_service() {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = tokio::process::Command::new("launchctl");
        c.args(["kickstart", "system/com.silicon.ting"]);
        c
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut c = tokio::process::Command::new("systemctl");
        c.args(["start", "silicon-ting.service"]);
        c
    };
    #[cfg(windows)]
    let mut command = {
        let mut c = tokio::process::Command::new("schtasks.exe");
        c.args(["/Run", "/TN", "SiliconTingDaemon"]);
        c
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), command.output()).await;
}
async fn daemon(
    profile: &Profile,
    api: &str,
    org: &str,
    op: &str,
    mut args: Value,
    start: bool,
) -> Result<Value> {
    let session = profile.session(api)?;
    let o = args.as_object_mut().unwrap();
    o.insert("op".into(), json!(op));
    o.insert("api_url".into(), json!(api));
    o.insert("org_id".into(), json!(org));
    o.insert("profile".into(), json!(profile.dir));
    o.insert("session_token".into(), json!(session.token));
    if start {
        start_service().await
    }
    ipc(args).await
}
async fn run(root: &ArgMatches) -> Result<Value> {
    if b(root, "version") {
        return Ok(json!({"version":env!("CARGO_PKG_VERSION")}));
    }
    let (name, m) = root
        .subcommand()
        .ok_or_else(|| Error::input("Choose a command; run ting --help."))?;
    if name == "docs" {
        let topic = required(m, "topic")?;
        return Ok(
            json!({"topic":topic,"content":if topic=="usage"{include_str!("../docs/cli.md")}else{include_str!("../docs/api.md")} }),
        );
    }
    if name == "iam" {
        return Ok(
            json!({"app_id":"tos>ting","api_version":"v1","repository_url":option_env!("TING_REPOSITORY_URL").unwrap_or("https://github.com/teamofsilicons/silicon-ting"),"docs_url":option_env!("TING_DOCS_URL").unwrap_or("https://ting.teamofsilicons.com/docs"),"rust_package":option_env!("TING_RUST_PACKAGE").unwrap_or("silicon-ting-client")}),
        );
    }
    let profile = Profile::current()?;
    let profile_mutation = name == "logout"
        || name == "login" && m.subcommand().is_none()
        || name == "config" && m.subcommand_name() == Some("set")
        || name == "org" && m.subcommand_name() == Some("use");
    let _profile_lock = if profile_mutation {
        Some(profile.lock()?)
    } else {
        None
    };
    let mut settings: Settings = profile.read("settings.json")?.unwrap_or_default();
    let selection = selection(root, &settings)?;
    if name == "config" {
        let (sub, m) = m.subcommand().unwrap();
        let enabled = settings.telemetry.unwrap_or(true);
        if sub == "list" {
            return Ok(json!({"telemetry.enabled":enabled}));
        }
        let key = required(m, "key")?;
        if key != "telemetry.enabled" {
            return Err(Error::input(
                "Unknown setting; only telemetry.enabled is supported.",
            ));
        }
        let value = if sub == "set" {
            let v = required(m, "value")? == "true";
            settings.telemetry = Some(v);
            profile.save("settings.json", &settings)?;
            v
        } else {
            enabled
        };
        return Ok(json!({"key":key,"value":value}));
    }
    if name == "org" && m.subcommand_name() == Some("current") {
        let org = selected(&selection)?;
        return Ok(json!({"org_id":org,"source":selection.as_ref().unwrap().1}));
    }
    let org_opt = selection.as_ref().map(|(s, _)| s.as_str());
    if name == "send" {
        return execute_proof(ProofOperation::Send, m, root, org_opt).await;
    }
    if name == "sent" {
        let (sub, m) = m.subcommand().unwrap();
        return execute_proof(
            if sub == "get" {
                ProofOperation::SentGet
            } else {
                ProofOperation::SentList
            },
            m,
            root,
            org_opt,
        )
        .await;
    }
    if name == "subscriptions" {
        let (sub, sm) = m.subcommand().unwrap();
        if sub == "register" || proof_mode(sm) {
            return execute_proof(
                match sub {
                    "register" => ProofOperation::Register,
                    "list" => ProofOperation::Subscriptions,
                    _ => ProofOperation::Revoke,
                },
                sm,
                root,
                org_opt,
            )
            .await;
        }
    }
    let api = origin(root)?;
    let client = Client::new(&api)?;
    let test = TestHeaders::environment()?;
    if name == "login" {
        if m.subcommand_name() == Some("status") {
            let sess = match profile.session(&api) {
                Ok(s) => s,
                Err(e) if e.code == "authentication_required" => {
                    return Ok(json!({"authenticated":false,"id":null}));
                }
                Err(e) => return Err(e),
            };
            return match client
                .json("GET", "/v1/me", None, Some(&sess.token), &test)
                .await
            {
                Ok(v) => Ok(json!({"authenticated":true,"id":v["id"]})),
                Err(e)
                    if ["authentication_required", "session_expired"]
                        .contains(&e.code.as_str()) =>
                {
                    Ok(json!({"authenticated":false,"id":null}))
                }
                Err(e) => Err(e),
            };
        }
        if profile.read::<Session>("session.json")?.is_some() {
            return Err(Error::input(
                "This profile already holds a session. Run logout or use another SILICON_HOME.",
            ));
        }
        let slt = match (s(m, "token"), b(m, "token-stdin")) {
            (Some(t), false) => {
                nonempty(t, "Token")?;
                t.to_owned()
            }
            (None, true) => secret(None)?,
            _ => {
                return Err(Error::input(
                    "Supply exactly one login token or --token-stdin.",
                ));
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let previous = profile.read::<Value>("login-attempt.json")?;
        let attempt = match previous {
            Some(a) if now.saturating_sub(a["created"].as_u64().unwrap_or(0)) <= 120 => {
                if a["api_url"] != api || a["slt"] != slt {
                    return Err(Error::new(
                        "login_attempt_pending",
                        "The previous login attempt has an uncertain outcome.",
                        "Retry its exact SLT against the original API within two minutes; then obtain a new SLT.",
                        false,
                    ));
                }
                a
            }
            Some(a) if a["slt"] == slt => {
                return Err(Error::new(
                    "login_attempt_expired",
                    "The login replay window expired.",
                    "Obtain a new IAM short-lived token to begin another login attempt.",
                    false,
                ));
            }
            _ => {
                let a = json!({"api_url":api,"slt":slt,"key":uuid::Uuid::new_v4().to_string(),"created":now});
                profile.save("login-attempt.json", &a)?;
                a
            }
        };
        let v = client
            .request(
                "POST",
                "/v1/session",
                Some(serde_json::to_vec(&json!({"slt":slt})).unwrap()),
                None,
                &test,
                attempt["key"].as_str(),
            )
            .await?;
        let sess = Session {
            api_url: api,
            id: v["id"].as_str().ok_or_else(Error::network)?.into(),
            token: v["session_token"]
                .as_str()
                .ok_or_else(Error::network)?
                .into(),
            context: v.get("context").cloned(),
        };
        profile.save("session.json", &sess)?;
        profile.remove("login-attempt.json")?;
        return Ok(json!({"authenticated":true,"id":sess.id}));
    }
    if name == "logout" {
        let sess = match profile.session(&api) {
            Ok(s) => s,
            Err(e) if e.code == "authentication_required" => {
                return Ok(json!({"authenticated":false}));
            }
            Err(e) => return Err(e),
        };
        let local = ipc(
            json!({"op":"logout","profile":profile.dir,"api_url":api,"session_token":sess.token}),
        )
        .await;
        let remote = client
            .json("DELETE", "/v1/session", None, Some(&sess.token), &test)
            .await;
        profile.remove("session.json")?;
        profile.remove("login-attempt.json")?;
        if let Err(e) = local {
            if e.code != "daemon_unavailable" {
                return Err(e);
            }
        }
        remote?;
        return Ok(json!({"authenticated":false}));
    }
    if name == "bug" {
        use base64::Engine;
        let (_, m) = m.subcommand().unwrap();
        let title = required(m, "title")?;
        if title.is_empty() || title.len() > 200 {
            return Err(Error::input("Title must contain 1 to 200 UTF-8 bytes."));
        }
        let body = match (s(m, "body"), s(m, "body-file")) {
            (Some(x), None) => x.to_owned(),
            (None, Some(p)) => fs::read_to_string(p)
                .map_err(|_| Error::input("Could not read UTF-8 report body."))?,
            _ => return Err(Error::input("Supply exactly one --body or --body-file.")),
        };
        if body.is_empty() {
            return Err(Error::input("Bug report body is required."));
        }
        let mut attachments = vec![];
        for p in m.get_many::<String>("attach").into_iter().flatten() {
            if attachments.len() == 8 {
                return Err(Error::input("At most eight attachments are allowed."));
            }
            let bytes = fs::read(p).map_err(|_| Error::input("Could not read an attachment."))?;
            let name = Path::new(p)
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::input("Attachment requires a UTF-8 basename."))?;
            let (encoding, content) = match String::from_utf8(bytes) {
                Ok(s) => ("utf-8", s),
                Err(e) => (
                    "base64",
                    base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
                ),
            };
            attachments.push(json!({"name":name,"encoding":encoding,"content":content}));
        }
        let pr = s(m, "pr");
        if let Some(p) = pr {
            webhook_url(p)?;
            if !p.starts_with("https://") || p.len() > 2048 {
                return Err(Error::input("PR URL must be HTTPS and at most 2048 bytes."));
            }
        }
        let body = json!({"title":title,"body":body,"pr_ref":pr,"attachments":attachments});
        if serde_json::to_vec(&body).unwrap().len() > 192 * 1024 {
            return Err(Error::input("Complete bug report exceeds 192 KiB."));
        }
        return recipient(&client, &profile, &test, "POST", "/v1/bugs", Some(body)).await;
    }
    if name == "org" {
        let (sub, m) = m.subcommand().unwrap();
        let v = recipient(&client, &profile, &test, "GET", "/v1/orgs", None).await?;
        if sub == "list" {
            return Ok(v);
        }
        let id = required(m, "id")?;
        nonempty(id, "Org")?;
        let canonical = v["items"]
            .as_array()
            .and_then(|xs| xs.iter().find(|x| x["id"] == id || x["handle"] == id))
            .and_then(|x| x["id"].as_str())
            .ok_or_else(|| {
                Error::new(
                    "permission_denied",
                    "The selected organisation is not accessible.",
                    "Choose an org shown by ting org list.",
                    false,
                )
            })?;
        settings.org = Some(canonical.into());
        profile.save("settings.json", &settings)?;
        return Ok(json!({"org_id":canonical,"saved":true}));
    }
    let org = selected(&selection)?;
    let base = format!("/v1/orgs/{}", segment(org));
    match name {
        "apps" => {
            let (_, m) = m.subcommand().unwrap();
            recipient(
                &client,
                &profile,
                &test,
                "GET",
                &query(&format!("{base}/apps"), &list_query(m, &[])),
                None,
            )
            .await
        }
        "types" => {
            let (sub, m) = m.subcommand().unwrap();
            if sub == "list" {
                return recipient(
                    &client,
                    &profile,
                    &test,
                    "GET",
                    &query(
                        &format!("{base}/apps/{}/types", segment(required(m, "app")?)),
                        &list_query(m, &[]),
                    ),
                    None,
                )
                .await;
            }
            let t = required(m, "type")?;
            let app = type_app(t)?;
            let d = required(m, "description")?;
            if d.is_empty() || d.len() > 1000 {
                return Err(Error::input(
                    "Description must contain 1 to 1000 UTF-8 bytes.",
                ));
            }
            let path = format!("{base}/apps/{}/types", segment(app));
            if sub == "register" {
                recipient(
                    &client,
                    &profile,
                    &test,
                    "POST",
                    &path,
                    Some(json!({"type":t,"description":d})),
                )
                .await
            } else {
                recipient(
                    &client,
                    &profile,
                    &test,
                    "PATCH",
                    &format!("{path}/{}", segment(t)),
                    Some(json!({"description":d})),
                )
                .await
            }
        }
        "subscriptions" => {
            let (sub, m) = m.subcommand().unwrap();
            if sub == "list" {
                recipient(
                    &client,
                    &profile,
                    &test,
                    "GET",
                    &query(
                        &format!("{base}/subscriptions"),
                        &list_query(m, &[("app", "app_id"), ("for", "for")]),
                    ),
                    None,
                )
                .await
            } else {
                recipient(
                    &client,
                    &profile,
                    &test,
                    "DELETE",
                    &format!("{base}/subscriptions/{}", segment(required(m, "id")?)),
                    None,
                )
                .await
            }
        }
        "inbox" => {
            let (sub, m) = m.subcommand().unwrap();
            match sub {
                "list" => {
                    let mut q =
                        list_query(m, &[("app", "app_id"), ("type", "type"), ("read", "read")]);
                    if !b(m, "all") {
                        q.push(("silent".into(), b(m, "silent").to_string()))
                    }
                    let mut v = recipient(
                        &client,
                        &profile,
                        &test,
                        "GET",
                        &query(&format!("{base}/inbox"), &q),
                        None,
                    )
                    .await?;
                    if let Some(items) = v["items"].as_array_mut() {
                        for item in items {
                            if let Some(o) = item.as_object_mut() {
                                o.remove("data");
                                o.remove("metadata");
                            }
                        }
                    }
                    Ok(v)
                }
                "get" => {
                    recipient(
                        &client,
                        &profile,
                        &test,
                        "GET",
                        &format!("{base}/inbox/{}", segment(required(m, "id")?)),
                        None,
                    )
                    .await
                }
                _ => {
                    let ids = unique_ids(m.get_many::<String>("ids").unwrap().cloned().collect())?;
                    recipient(
                        &client,
                        &profile,
                        &test,
                        "POST",
                        &format!("{base}/inbox/read"),
                        Some(json!({"message_ids":ids})),
                    )
                    .await
                }
            }
        }
        "preferences" => {
            let (sub, m) = m.subcommand().unwrap();
            if let Some(t) = s(m, "type") {
                let app = type_app(t)?;
                if s(m, "app").is_some_and(|a| a != app) {
                    return Err(Error::input("Type must belong to the selected app."));
                }
            }
            let path = format!("{base}/preferences");
            if sub == "set" {
                recipient(&client,&profile,&test,"PUT",&path,Some(json!({"app_id":required(m,"app")?,"service":s(m,"service"),"type":s(m,"type"),"enabled":required(m,"enabled")?=="true"}))).await
            } else {
                let mut q = list_query(
                    m,
                    &[("app", "app_id"), ("service", "service"), ("type", "type")],
                );
                if sub == "reset" {
                    q.retain(|(k, _)| k != "limit" && k != "cursor")
                }
                recipient(
                    &client,
                    &profile,
                    &test,
                    if sub == "list" { "GET" } else { "DELETE" },
                    &query(&path, &q),
                    None,
                )
                .await
            }
        }
        "webhook" => {
            if let Some((_, sm)) = m.subcommand() {
                let mut v = recipient(
                    &client,
                    &profile,
                    &test,
                    "GET",
                    &query(&format!("{base}/webhooks"), &list_query(sm, &[])),
                    None,
                )
                .await?;
                let local = daemon(&profile, &api, org, "destinations", json!({}), false)
                    .await
                    .unwrap_or(json!({}));
                if let Some(items) = v["items"].as_array_mut() {
                    for x in items {
                        let id = x["id"].as_str().unwrap_or("").to_owned();
                        x["url"] = local.get(&id).cloned().unwrap_or(Value::Null);
                        x.as_object_mut().unwrap().remove("receiver_id");
                    }
                }
                return Ok(v);
            }
            let url = required(m, "url")?;
            webhook_url(url)?;
            if let Some(h) = s(m, "health-url") {
                webhook_url(h)?
            }
            let sec = if b(m, "secret-stdin") {
                Some(secret(None)?)
            } else {
                None
            };
            daemon(&profile,&api,org,"webhook",json!({"url":url,"id":s(m,"id"),"secret":sec,"clear_secret":b(m,"clear-secret"),"health_url":s(m,"health-url"),"clear_health_url":b(m,"clear-health-url"),"takeover":b(m,"takeover"),"headers":test}),true).await
        }
        "unhook" => {
            let id = required(m, "id")?;
            match daemon(
                &profile,
                &api,
                org,
                "unhook",
                json!({"id":id,"headers":test}),
                false,
            )
            .await
            {
                Err(e) if e.code == "daemon_unavailable" => {
                    recipient(
                        &client,
                        &profile,
                        &test,
                        "DELETE",
                        &format!("{base}/webhooks/{}", segment(id)),
                        None,
                    )
                    .await
                }
                result => result,
            }
        }
        "daemon" => {
            let (sub, _) = m.subcommand().unwrap();
            let v = daemon(
                &profile,
                &api,
                org,
                sub,
                json!({"headers":test}),
                sub == "reconnect",
            )
            .await;
            if sub == "status" {
                match v {
                    Err(e) if e.code == "daemon_unavailable" => {
                        Ok(json!({"running":false,"socket_connected":false,"pending":null}))
                    }
                    x => x,
                }
            } else {
                v
            }
        }
        _ => Err(Error::input("Unsupported command.")),
    }
}
#[tokio::main]
async fn main() {
    let json = std::env::args().any(|s| s == "--json");
    let matches = match cli().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            if e.use_stderr() {
                if json {
                    eprintln!("{}", Error::input(e.to_string()).envelope())
                } else {
                    eprint!("{e}")
                }
                std::process::exit(2)
            } else {
                print!("{e}");
                return;
            }
        }
    };
    let started = std::time::Instant::now();
    let result = run(&matches).await;
    let mut leaf = &matches;
    while let Some((_, sub)) = leaf.subcommand() {
        leaf = sub;
    }
    if let Some((command, _)) = matches.subcommand() {
        if result.is_ok()
            && !["docs", "iam", "config", "org"].contains(&command)
            && s(leaf, "write-request").is_none()
        {
            if let (Ok(api), Ok(profile)) = (origin(&matches), Profile::current()) {
                if profile
                    .read::<Settings>("settings.json")
                    .ok()
                    .flatten()
                    .unwrap_or_default()
                    .telemetry
                    .unwrap_or(true)
                {
                    telemetry(&api,"cli_command",json!({"command":command,"success":result.is_ok(),"duration_ms":started.elapsed().as_millis().min(u64::MAX as u128) as u64})).await;
                }
            }
        }
    }
    match result {
        Ok(v) => {
            if !json && v.get("content").is_some() {
                println!("{}", v["content"].as_str().unwrap_or(""))
            } else if json {
                println!("{v}")
            } else {
                println!("{}", serde_json::to_string_pretty(&v).unwrap())
            }
        }
        Err(e) => {
            if json {
                eprintln!("{}", e.envelope())
            } else {
                eprintln!("{e}")
            }
            std::process::exit(if e.code == "invalid_input" { 2 } else { 1 })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_contract() {
        cli().debug_assert();
        assert!(
            cli()
                .try_get_matches_from(["ting", "inbox", "list", "--silent", "--all"])
                .is_err()
        );
        assert!(
            cli()
                .try_get_matches_from([
                    "ting",
                    "preferences",
                    "set",
                    "--app",
                    "tos>dm",
                    "--enabled",
                    "yes"
                ])
                .is_err()
        );
        assert!(
            cli()
                .try_get_matches_from(["ting", "send", "--request-file", "x", "--json"])
                .is_ok()
        );
    }
}
