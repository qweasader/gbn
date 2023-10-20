# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

##############################################################################
# CLASS: Win32_Service Functions
#
# - wmi_svc_prop  - Returns List of Service with Properties.
# - wmi_svc       - Returns List of Service Names.
# - wmi_svc_state - Returns State of Service, Ex, Stopped/Running.
# - wmi_svc_path  - Returns running service installed path.
#
# If svcName = "AppMgmt", returns details of the service.
#
##############################################################################

function wmi_svc_prop(handle, svcName)
{
  if(!svcName){
    query = "Select * from Win32_Service";
  }
  else {
    query = 'Select * from Win32_Service Where Name = ' +
             raw_string(0x22) + svcName + raw_string(0x22);
  }

  svcList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< svcList) || !svcList){
    return(0);
  }

  return wmi_misc_split_res(List:svcList);
}

function wmi_svc(handle, svcName)
{
  if(!svcName){
    query = "Select Caption from Win32_Service";
  }
  else {
    query = 'Select Caption from Win32_Service Where Name = ' +
             raw_string(0x22) + svcName + raw_string(0x22);
  }

  svcList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< svcList) || !svcList){
    return(0);
  }

  svcList = ereg_replace(pattern:"\|", string:svcList, replace:" - ");
  return svcList;
}

function wmi_svc_state(handle, svcName)
{
  if(!svcName){
    query = "Select State from Win32_Service";
  }
  else {
    query = 'Select State from Win32_Service Where Name = ' +
             raw_string(0x22) + svcName + raw_string(0x22);
  }

  svcList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< svcList) || !svcList){
    return(0);
  }

  svcList = ereg_replace(pattern:"\|", string:svcList, replace:" - ");
  return svcList;
}

function wmi_svc_path(handle, svcName)
{
  if(!svcName){
    query = "Select PathName from Win32_Service";
  }
  else {
    query = 'Select PathName from Win32_Service Where Name = ' +
             raw_string(0x22) + svcName + raw_string(0x22);
  }

  svcList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< svcList) || !svcList){
    return(0);
  }

  svcList = ereg_replace(pattern:"[.a-zA-Z0-9_ ]+\|" + '\\"?', string:svcList, replace:"");
  return svcList;
}
