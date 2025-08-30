// use std::error::Error;
use std::fmt::Error;
use std::fs;
use std::path::Path;
use std::fs::metadata;

use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::shadow::{Shadow, ShadowHooks};
use libnss::{
    libnss_group_hooks, libnss_passwd_hooks,
    libnss_shadow_hooks,
};

use rusqlite::Connection;

struct JITPasswd;
libnss_passwd_hooks!(jit, JITPasswd);

impl PasswdHooks for JITPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        // Connect to the database
        let conn = connect_to_file_database("/etc/libnss-jit/libnss-jit.sqlite".to_string());

        if conn.is_err() {
            return Response::NotFound;
        }

        let users = get_all_users(&(conn.unwrap()));

        if users.is_ok() {
            return Response::Success(users.unwrap());
        }

        Response::NotFound
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        // Connect to the database
        let conn = connect_to_file_database("/etc/libnss-jit/libnss-jit.sqlite".to_string());

        if conn.is_err() {
            return Response::NotFound;
        }

        let user = get_user_by_uid(&(conn.unwrap()), uid);

        if user.is_ok() {
            return Response::Success(user.unwrap());
        }

        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        // Connect to the database
        let conn = connect_to_file_database("/etc/libnss-jit/libnss-jit.sqlite".to_string());

        if conn.is_err() {
            return Response::NotFound;
        }

        let user = get_user_by_name(&(conn.unwrap()), name);

        if user.is_ok() {
            return Response::Success(user.unwrap());
        }

        Response::NotFound
    }
}

struct JITGroup;
libnss_group_hooks!(jit, JITGroup);

impl GroupHooks for JITGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        Response::Success(vec![Group {
            name: "test".to_string(),
            passwd: "".to_string(),
            gid: 1005,
            members: vec!["someone".to_string()],
        }])
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        if gid == 1005 {
            return Response::Success(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            });
        }

        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        if name == "test" {
            return Response::Success(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            });
        }

        Response::NotFound
    }
}

struct JITShadow;
libnss_shadow_hooks!(jit, JITShadow);

impl ShadowHooks for JITShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        // TODO: Ensure we are a privileged user before returning results
        Response::Success(vec![
            Shadow {
                name: "test".to_string(),
                passwd: "!".to_string(),
                last_change: -1,
                change_min_days: -1,
                change_max_days: -1,
                change_warn_days: -1,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            }
        ])
    }

    fn get_entry_by_name(name: String) -> Response<Shadow> {
        // TODO: Ensure we are a privileged user before returning results
        if name == "test" {
            return Response::Success(Shadow {
                name: "test".to_string(),
                passwd: "!".to_string(),
                last_change: -1,
                change_min_days: -1,
                change_max_days: -1,
                change_warn_days: -1,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            });
        }

        Response::NotFound
    }
}


fn get_user_by_name(conn: &Connection, name: String) -> Result<Passwd, rusqlite::Error>  {
    let mut users = Vec::new();

    // Query the database for users
    let mut stmt = conn.prepare(
        "SELECT name, passwd, uid, gid, gecos, dir, shell FROM users WHERE name = ?1"
    )?;

    let mut rows = stmt.query([name])?;

    while let Some(row) = rows.next()? {
        users.push(Passwd {
            name: row.get(0)?,
            passwd: row.get(1)?,
            uid: row.get(2)?,
            gid: row.get(3)?,
            gecos: row.get(4)?,
            dir: row.get(5)?,
            shell: row.get(6)?,
        });
    }

    if users.len() == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }

    Ok(users[0].clone())
}

fn get_user_by_uid(conn: &Connection, uid: libc::uid_t) -> Result<Passwd, rusqlite::Error> {
    let mut users = Vec::new();

    // Query the database for users
    let mut stmt = conn.prepare(
        "SELECT name, passwd, uid, gid, gecos, dir, shell FROM users WHERE uid = ?1"
    )?;

    let mut rows = stmt.query([uid])?;

    while let Some(row) = rows.next()? {
        users.push(Passwd {
            name: row.get(0)?,
            passwd: row.get(1)?,
            uid: row.get(2)?,
            gid: row.get(3)?,
            gecos: row.get(4)?,
            dir: row.get(5)?,
            shell: row.get(6)?,
        });
    }

    if users.len() == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }

    Ok(users[0].clone())
}

fn get_all_users(conn: &Connection) -> Result<Vec<Passwd>, rusqlite::Error> {
    let mut users = Vec::new();

    // Query the database for users
    let mut stmt = conn.prepare(
        "SELECT name, passwd, uid, gid, gecos, dir, shell FROM users"
    )?;

    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        users.push(Passwd {
            name: row.get(0)?,
            passwd: row.get(1)?,
            uid: row.get(2)?,
            gid: row.get(3)?,
            gecos: row.get(4)?,
            dir: row.get(5)?,
            shell: row.get(6)?,
        });
    }

    Ok(users)
}

fn connect_to_file_database(path: String) -> Result<Connection, Error>
{
    let conn = Connection::open(path).expect("Failed to open database");

    init_database_schema(&conn);

    Ok(conn)
}

fn connect_to_in_memory_database() -> Result<Connection, String>
{
    let conn = Connection::open_in_memory().expect("Unable to open database");

    init_database_schema(&conn);

    return Ok(conn)
}

fn init_database_schema(conn: &Connection)
{
    create_users_table(&conn);
    create_groups_table(&conn);
    create_group_members_table(&conn);
    create_shadows_table(&conn);
}

fn create_users_table(conn: &Connection)
{
    // Create passwd table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            name TEXT NOT NULL,
            passwd TEXT NOT NULL,
            uid INTEGER NOT NULL,
            gid INTEGER NOT NULL,
            gecos TEXT NOT NULL,
            dir TEXT NOT NULL,
            shell TEXT NOT NULL,
            PRIMARY KEY (name, uid)
        )",
        [],
    ).expect("Failed to create users table");
}

fn create_groups_table(conn: &Connection)
{
    // Create group table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS groups (
            name TEXT NOT NULL,
            passwd TEXT NOT NULL,
            gid INTEGER NOT NULL,
            PRIMARY KEY (name, gid)
        )",
        [],
    ).expect("Failed to create groups table");
}

fn create_group_members_table(conn: &Connection)
{
    conn.execute(
        "CREATE TABLE IF NOT EXISTS group_members (
            gid INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            FOREIGN KEY (gid) REFERENCES groups(gid),
            FOREIGN KEY (uid) REFERENCES users(uid),
            PRIMARY KEY (gid, uid)
        )",
        [],
    ).expect("Failed to create group_members table");
}

fn create_shadows_table(conn: &Connection)
{
    conn.execute(
        "CREATE TABLE IF NOT EXISTS shadows (
            name TEXT PRIMARY KEY,
            passwd TEXT NOT NULL,
            last_change INTEGER NOT NULL,
            change_min_days INTEGER NOT NULL,
            change_max_days INTEGER NOT NULL,
            change_warn_days INTEGER NOT NULL,
            change_inactive_days INTEGER NOT NULL,
            expire_date INTEGER NOT NULL,
            reserved INTEGER NOT NULL
        )",
        [],
    ).expect("Failed to create shadows table");
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    fn init_passwd_table(conn: &Connection) {
        conn.execute(
            "INSERT INTO users (name, passwd, uid, gid, gecos, dir, shell) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["test", "x", 1005, 1005, "Test User", "/home/test", "/bin/bash"],
        ).expect("Failed to insert test user");
        conn.execute(
            "INSERT INTO users (name, passwd, uid, gid, gecos, dir, shell) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["test1", "x", 1006, 1006, "Test User1", "/home/test1", "/bin/bash"],
        ).expect("Failed to insert test user");
    }

    #[test]
    fn test_get_all_users() {
        let conn = connect_to_in_memory_database().unwrap();
        init_passwd_table(&conn);

        let response = get_all_users(&conn);

        let users = response.unwrap();
        assert!(users.len() == 2);
    }

    #[test]
    fn test_get_user_by_name() {
        let conn = connect_to_in_memory_database().unwrap();
        init_passwd_table(&conn);

        let response = get_user_by_name(&conn, "test1".to_string());

        let user = response.unwrap();
        assert!(user.name == "test1");
        assert!(user.uid == 1006);
        assert!(user.gid == 1006);

    }

    #[test]
    fn test_get_user_by_name_doesnt_exist() {
        let conn = connect_to_in_memory_database().unwrap();
        init_passwd_table(&conn);

        let response = get_user_by_name(&conn, "asdf".to_string());

        assert!(response.is_err());
        assert!(response.err().unwrap() == rusqlite::Error::QueryReturnedNoRows);
    }

    #[test]
    fn test_get_user_by_uid() {
        let conn = connect_to_in_memory_database().unwrap();
        init_passwd_table(&conn);

        let response = get_user_by_uid(&conn, 1005);

        let user = response.unwrap();
        assert!(user.name == "test");
        assert!(user.uid == 1005);
        assert!(user.gid == 1005);
    }
}