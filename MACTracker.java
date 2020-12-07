package net.floodlightcontroller.mactracker;
 
import java.util.Collection;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
 
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.VlanVid;
import org.projectfloodlight.openflow.types.*;
 
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import net.floodlightcontroller.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.*;
 
public class MACTracker implements IOFMessageListener, IFloodlightModule {
 
    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected Set<String> ipaddress;
    protected static Logger logger;
    protected int count = 0;
    protected boolean triggered = false;
    Timer timer = new Timer();
    TimerTask task = new Helper(); 

    @Override
    public String getName() {
        return MACTracker.class.getSimpleName();
    }
 
    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }
 
    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }
 
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }
 
    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }
 
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {

        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;

    }
 
    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {

        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        ipaddress = new ConcurrentSkipListSet<String>();
        logger = LoggerFactory.getLogger(MACTracker.class);
        timer.schedule(task, 9000,9000);

    }
 
    @Override
    public void startUp(FloodlightModuleContext context) {

        logger.info("mactracker started");
        System.out.println("-------------------Started--------------------");
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

    }

    public void anom(){

        if(!triggered){
            logger.info("Anomoly detected.");
            triggered = true;
        }

    }
 
    class Helper extends TimerTask 
    { 
        public void run() 
        { 
             triggered = false;
             count = 0;
             ipaddress.clear();
        } 
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
        case PACKET_IN:
            /* Retrieve the deserialized packet in message */
            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
    
            /* Various getters and setters are exposed in Ethernet */
            MacAddress srcMac = eth.getSourceMACAddress();
            VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID());
    
            /* 
            * Check the ethertype of the Ethernet frame and retrieve the appropriate payload.
            * Note the shallow equality check. EthType caches and reuses instances for valid types.
            */
            if (eth.getEtherType() == EthType.IPv4) {
                /* We got an IPv4 packet; get the payload from Ethernet */
                IPv4 ipv4 = (IPv4) eth.getPayload();
                
                /* Various getters and setters are exposed in IPv4 */
                byte[] ipOptions = ipv4.getOptions();
                IPv4Address dstIp = ipv4.getDestinationAddress();
                
                /* 
                * Check the IP protocol version of the IPv4 packet's payload.
                */
                if (ipv4.getProtocol() == IpProtocol.TCP) {
                    /* We got a TCP packet; get the payload from IPv4 */
                    TCP tcp = (TCP) ipv4.getPayload();
    
                    /* Various getters and setters are exposed in TCP */
                    TransportPort srcPort = tcp.getSourcePort();
                    TransportPort dstPort = tcp.getDestinationPort();
                    short flags = tcp.getFlags();
                    
                    /* Your logic here! */
                    //logger.info(String.valueOf(flags));
                    if(!ipaddress.contains(ipv4.getSourceAddress().toString())){

                        ipaddress.add(ipv4.getSourceAddress().toString());
                        count++;

                    }
                    /*if(flags == 511){
                        anom();
                    }*/
                    if(count >= 1000){
                        anom();
                    }

                } else if (ipv4.getProtocol() == IpProtocol.UDP) {
                    /* We got a UDP packet; get the payload from IPv4 */
                    UDP udp = (UDP) ipv4.getPayload();
    
                    /* Various getters and setters are exposed in UDP */
                    TransportPort srcPort = udp.getSourcePort();
                    TransportPort dstPort = udp.getDestinationPort();
                    
                    /* Your logic here! */
                }
    
            } else if (eth.getEtherType() == EthType.ARP) {
                /* We got an ARP packet; get the payload from Ethernet */
                ARP arp = (ARP) eth.getPayload();
    
                /* Various getters and setters are exposed in ARP */
                boolean gratuitous = arp.isGratuitous();
    
            } else {
                /* Unhandled ethertype */
            }
            break;
        default:
            break;
        }
        return Command.CONTINUE;
    }
 
}