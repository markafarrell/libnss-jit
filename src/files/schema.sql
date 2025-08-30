CREATE TABLE IF NOT EXISTS users (
    name TEXT NOT NULL,
    passwd TEXT NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    gecos TEXT NOT NULL,
    dir TEXT NOT NULL,
    shell TEXT NOT NULL,
    PRIMARY KEY (name, uid)
);

CREATE TABLE IF NOT EXISTS groups (
    name TEXT NOT NULL,
    passwd TEXT NOT NULL,
    gid INTEGER NOT NULL,
    PRIMARY KEY (name, gid)
);

CREATE TABLE IF NOT EXISTS groups_members (
    gid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    FOREIGN KEY (gid) REFERENCES groups(gid),
    FOREIGN KEY (uid) REFERENCES users(uid),
    PRIMARY KEY (gid, uid)
);

CREATE TABLE IF NOT EXISTS shadows (
    name TEXT PRIMARY KEY,
    passwd TEXT NOT NULL,
    last_change INTEGER NOT NULL,
    change_min_days INTEGER NOT NULL,
    change_max_days INTEGER NOT NULL,
    change_warn_days INTEGER NOT NULL,
    change_inactive_days INTEGER NOT NULL,
    expire_date INTEGER NOT NULL,
    reserved INTEGER NOT NULL
);

INSERT INTO users (name, passwd, uid, gid, gecos, dir, shell)
VALUES ('test', 'x', 1005, 1005, 'test', '/home/test', '/bin/bash');
