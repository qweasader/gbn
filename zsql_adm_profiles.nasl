# Copyright (C) 2020 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150205");
  script_version("2020-06-16T13:40:33+0000");
  script_tag(name:"last_modification", value:"2020-06-16 13:40:33 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-04-09 12:11:42 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Content of ADM_PROFILES Database");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"This script writes the complete database of ADM_PROFILES to KB.

  Note:This script stores values in KB only and has no output.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/zsql/zsql_adm_role_privs/ssh/ERROR", value:TRUE);
  exit(0);
}

query = 'dump table ADM_PROFILES into file \'STDOUT\' COLUMNS TERMINATED BY \'|\';';
db_adm_roles = zsql_command(socket:sock, query:query);

if(!db_adm_roles){
  set_kb_item(name:"Policy/zsql/adm_profiles/ERROR", value:TRUE);
}else{
  foreach line(split(db_adm_roles, keep:FALSE)){
    if(line =~ "SQL>")
      line = str_replace(string:line, find:"SQL> ", replace:"");

    items = eregmatch(string:line, pattern:"(.*)\|(.*)\|(.*)\|(.*)");
    #PROFILE,RESOURCE_NAME,RESOURCE_TYPE,THRESHOLD
    if(items){
      set_kb_item(name:"Policy/zsql/adm_profiles/"+items[2]+"/profile", value:items[1]);
      set_kb_item(name:"Policy/zsql/adm_profiles/"+items[2]+"/resource_type", value:items[3]);
      set_kb_item(name:"Policy/zsql/adm_profiles/"+items[2]+"/threshold", value:items[4]);
    }else{
     set_kb_item(name:"Policy/zsql/adm_profiles/empty", value:TRUE);
    }
  }
}

exit(0);