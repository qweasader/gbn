# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.123890");
  script_cve_id("CVE-2012-2664");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T09:12:43+0000");
  script_tag(name:"last_modification", value:"2022-04-05 09:12:43 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2012-0958)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0958");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0958.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos' package(s) announced via the ELSA-2012-0958 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2-29.0.1.el6]
- Direct traceroute to linux.oracle.com (John Haxby) [orabug 11713272]
- Disable --upload option as it will not work with Oracle support
- Check oraclelinux-release instead of redhat-release to get OS version (John Haxby) [bug 11681869]
- Remove RH ftp URL and support email
- add sos-oracle-enterprise.patch

[2.2-29.el6]
- Collect the swift configuration directory in gluster module
 Resolves: bz822442
- Update IPA module and related plug-ins
 Resolves: bz812395

[2.2-28.el6]
- Collect mcelog files in the hardware module
 Resolves: bz810702

[2.2-27.el6]
- Add nfs statedump collection to gluster module
 Resolves: bz752549

[2.2-26.el6]
- Use wildcard to match possible libvirt log paths
 Resolves: bz814474

[2.2-25.el6]
- Add forbidden paths for new location of gluster private keys
 Resolves: bz752549

[2.2-24.el6]
- Fix katello and aeolus command string syntax
 Resolves: bz752666
- Remove stray hunk from gluster module patch
 Resolves: bz784061

[2.2-22.el6]
- Correct aeolus debug invocation in CloudForms module
 Resolves: bz752666
- Update gluster module for gluster-3.3
 Resolves: bz784061
- Add additional command output to gluster module
 Resolves: bz768641
- Add support for collecting gluster configuration and logs
 Resolves: bz752549

[2.2-19.el6]
- Collect additional diagnostic information for realtime systems
 Resolves: bz789096
- Improve sanitization of RHN user and case number in report name
 Resolves: bz771393
- Fix verbose output and debug logging
 Resolves: bz782339
- Add basic support for CloudForms data collection
 Resolves: bz752666
- Add support for Subscription Asset Manager diagnostics
 Resolves: bz752670

[2.2-18.el6]
- Collect fence_virt.conf in cluster module
 Resolves: bz760995
- Fix collection of /proc/net directory tree
 Resolves: bz730641
- Gather output of cpufreq-info when present
 Resolves: bz760424
- Fix brctl showstp output when bridges contain multiple interfaces
 Resolves: bz751273
- Add /etc/modprobe.d to kernel module
 Resolves: bz749919
- Ensure relative symlink targets are correctly handled when copying
 Resolves: bz782589
- Fix satellite and proxy package detection in rhn plugin
 Resolves: bz749262
- Collect stderr output from external commands
 Resolves: bz739080
- Collect /proc/cgroups in the cgroups module
 Resolve: bz784874
- Collect /proc/irq in the kernel module
 Resolves: bz784862
- Fix installed-rpms formatting for long package names
 Resolves: bz767827
- Add symbolic links for truncated log files
 Resolves: bz766583
- Collect non-standard syslog and rsyslog log files
 Resolves: bz771501
- Use correct paths for tomcat6 in RHN module
 Resolves: bz749279
- Obscure root password if present in anacond-ks.cfg
 Resolves: bz790402
- Do not accept embedded forward slashes in RHN usernames
 Resolves: bz771393
- Add new sunrpc module to collect rpcinfo for gluster systems
 Resolves: bz784061");

  script_tag(name:"affected", value:"'sos' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"sos", rpm:"sos~2.2~29.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
