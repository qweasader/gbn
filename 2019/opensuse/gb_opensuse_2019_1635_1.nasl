# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852596");
  script_version("2021-09-07T12:01:40+0000");
  script_cve_id("CVE-2018-16837", "CVE-2018-16859", "CVE-2018-16876", "CVE-2019-3828");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-29 17:14:00 +0000 (Fri, 29 May 2020)");
  script_tag(name:"creation_date", value:"2019-06-28 02:00:53 +0000 (Fri, 28 Jun 2019)");
  script_name("openSUSE: Security Advisory for ansible (openSUSE-SU-2019:1635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"openSUSE-SU", value:"2019:1635-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00079.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible'
  package(s) announced via the openSUSE-SU-2019:1635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ansible fixes the following issues:

  Ansible was updated to version 2.8.1:

  Full changelog is at /usr/share/doc/packages/ansible/changelogs/

  - Bugfixes

  - ACI - DO not encode query_string

  - ACI modules - Fix non-signature authentication

  - Add missing directory provided via ``--playbook-dir`` to adjacent
  collection loading

  - Fix 'Interface not found' errors when using eos_l2_interface with
  nonexistent interfaces configured

  - Fix cannot get credential when `source_auth` set to `credential_file`.

  - Fix netconf_config backup string issue

  - Fix privilege escalation support for the docker connection plugin when
  credentials need to be supplied (e.g. sudo with password).

  - Fix vyos cli prompt inspection

  - Fixed loading namespaced documentation fragments from collections.

  - Fixing bug came up after running cnos_vrf module against coverity.

  - Properly handle data importer failures on PVC creation, instead of
  timing out.

  - To fix the ios static route TC failure in CI

  - To fix the nios member module params

  - To fix the nios_zone module idempotency failure

  - add terminal initial prompt for initial connection

  - allow include_role to work with ansible command

  - allow python_requirements_facts to report on dependencies containing
  dashes

  - asa_config fix

  - azure_rm_roledefinition - fix a small error in build scope.

  - azure_rm_virtualnetworkpeering - fix cross subscriptions virtual
  network peering.

  - cgroup_perf_recap - When not using file_per_task, make sure we don't
  prematurely close the perf files

  - display underlying error when reporting an invalid ``tasks:`` block.

  - dnf - fix wildcard matching for state: absent

  - docker connection plugin - accept version ``dev`` as 'newest version'
  and print warning.

  - docker_container - ``oom_killer`` and ``oom_score_adj`` options are
  available since docker-py 1.8.0, not 2.0.0 as assumed by the version
  check.

  - docker_container - fix network creation when
  ``networks_cli_compatible`` is enabled.

  - docker_container - use docker API's ``restart`` instead of
  ``stop``/``start`` to restart a container.

  - docker_image - if ``build`` was not specified, the wrong default for
  ``build.rm`` is used.

  - docker_image - if ``nocache`` set to ``yes`` but not
  ``build.nocache``, the module failed.

  - docker_image - module failed when ``source: build`` was set but
  ``build.path`` options not specified.

  - docker_network module - fix idempotency when using ``aux_addresses``
  in ``ipam_config``.

  - ec2_instance - make Name tag idempotent

  - eos: don't f ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ansible' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.8.1~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.8.1~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
