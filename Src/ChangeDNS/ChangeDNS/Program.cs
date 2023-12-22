using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using NetFwTypeLib;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.IO;

namespace ChangeDNS
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Actual DNS Server Address:");
            Console.WriteLine(GetDNS());
            Console.WriteLine("Enter a new DNS server IP:");
            string DNSIP = Console.ReadLine(); 
            string readtext = File.ReadAllText("setup.cmd");
            string readtextreplaced = readtext.Replace("DNSIP", DNSIP);
            File.WriteAllText("setup.cmd", readtextreplaced);
            ProcessStartInfo startInfo = new ProcessStartInfo("setup.cmd");
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.Verb = "runas";
            startInfo.UseShellExecute = true;
            Process.Start(startInfo);
            File.WriteAllText("setup.cmd", readtext);
            rulesToFirewall("dns", DNSIP, true, NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP, NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT, NET_FW_ACTION_.NET_FW_ACTION_ALLOW, "", "Dnscache", "49152-65535", "443");
            Console.WriteLine("done");
            Console.ReadLine();
        }
        static string GetDNS()
        {
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                    IPAddressCollection dnsAddresses = ipProperties.DnsAddresses;
                    foreach (IPAddress dnsAdress in dnsAddresses)
                    {
                        return dnsAdress.ToString();
                    }
                }
            }
            return "not found";
        }
        private static void rulesToFirewall(string name, string ip, bool enabled, NET_FW_IP_PROTOCOL_ protocol, NET_FW_RULE_DIRECTION_ direction, NET_FW_ACTION_ action, string appname, string svcname, string localports, string remoteports)
        {
            INetFwRule2 newRule;
            INetFwPolicy2 firewallpolicy;
            newRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            newRule.Name = name;
            newRule.Protocol = (int)protocol;
            if (ip != "")
                newRule.RemoteAddresses = ip;
            newRule.Enabled = enabled;
            newRule.Direction = direction;
            newRule.InterfaceTypes = "All";
            newRule.Action = action;
            if (appname != "")
                newRule.ApplicationName = appname;
            if (svcname != "")
                newRule.serviceName = svcname;
            if (localports != "")
                newRule.LocalPorts = localports;
            if (remoteports != "")
                newRule.RemotePorts = remoteports;
            newRule.EdgeTraversal = false;
            firewallpolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            firewallpolicy.Rules.Remove(name);
            firewallpolicy.Rules.Add(newRule);
        }
    }
}