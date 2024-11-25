# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145872");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-04-30 08:13:40 +0000 (Fri, 30 Apr 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("PostgreSQL Trust Authentication Enabled (PostgreSQL Protocol)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("postgresql/tcp/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Trust Authentication mode is enabled in PostgreSQL.");

  script_tag(name:"vuldetect", value:"Tries to access PostgreSQL without authentication and checks
  the response.");

  script_tag(name:"insight", value:"The PostgreSQL server is running in 'trust mode'. This enables
  anyone who can connect to the server to access the database.");

  script_tag(name:"impact", value:"An unauthenticated user may access the underlying database and
  read/alter it (e.g. adding a new superuser account).");

  script_tag(name:"solution", value:"Choose another authentication method which enables secure
  authentication.");

  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/auth-trust.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/9.2/auth-methods.html#AUTH-TRUST");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("postgresql.inc");

if (!port = get_app_port(cpe: CPE, service: "postgresql"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

user = "postgres";
password = "";
db = "postgres";

if (postgresql_login(socket: soc, user: user, password: password, db: db)) {
  close(soc);
  report = 'It was possible to authenticate to the PostgreSQL database with the following credentials:\n\n' +
           'Username:  ' + user + '\nPassword:  (no password)\nDatabase:  ' + db;
  security_message(port: port, data: report);
  exit(0);
}

close(soc);

exit(99);
