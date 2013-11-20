drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  email text not null,
  name text not null,
  team_id integer,
  pw_hash text not null
);

drop table if exists team;
create table team (
    team_id integer primary key autoincrement,
    name text not null
);
