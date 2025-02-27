/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    public static HostBlackListsValidator hostBlackListsValidator;
    private static final int BLACK_LIST_ALARM_COUNT=5;
    public static  int checkedListsCount=0;
    public static  int ocurrencesCount=0;


    public static LinkedList<Integer> blackListOcurrences=new LinkedList<>();

    public static HostBlackListsValidator getHostBlackValidator(){
        if(hostBlackListsValidator==null){
            hostBlackListsValidator = new HostBlackListsValidator();
        }
        return hostBlackListsValidator;
    }

    public synchronized void setCantOcurrence(int mas){
        ocurrencesCount+= mas;
    }

    public synchronized void setCheckedListsCount(int mas){
        checkedListsCount += mas;
    }

    public synchronized void agregarNuevoRegistro(int i){
        blackListOcurrences.add(i);
    }

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int cantHilos){
        
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        

        int divisonCiclos = skds.getRegisteredServersCount()/cantHilos;
        System.out.println(skds.getRegisteredServersCount());

        for(int j= 0; j<=cantHilos;j+=1){
            //System.out.println(j*divisonCiclos+" el otro "+(j*divisonCiclos+divisonCiclos));
            BlackListThread hilo = new BlackListThread(ipaddress,j*divisonCiclos,j*divisonCiclos+divisonCiclos);  
            if(ocurrencesCount==5){
                break;
            }else{
            hilo.start();
            checkedListsCount+= hilo.getCheckedListsCount();
            ocurrencesCount+= hilo.getCantOcurrence();
        }
        }
        if (blackListOcurrences.size()>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
            
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }
        
        int ultimo;
        if(blackListOcurrences.isEmpty()){
            ultimo =skds.getRegisteredServersCount();
        }else{
            ultimo =blackListOcurrences.getLast();
        }                
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{ultimo, skds.getRegisteredServersCount()});
        
        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());

    public int getCantOcurrence() {
            return ocurrencesCount;
    }
    
    
    
}
