package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

public class BlackListThread extends Thread {
    String ipaddress;
    int start = 0;
    int end = 0;
    int checkedListsCount;
    int ocurrencesCount;
    HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();


    BlackListThread(String ipaddress,int start,int end){
        this.ipaddress = ipaddress;
        this.start = start;
        this.end = end;
        this.checkedListsCount = 0;
        this.ocurrencesCount = 0;
    }

    public int getCantOcurrence(){
        return ocurrencesCount;
    }

    public int getCheckedListsCount() {
        return checkedListsCount;
    }

    public void run() {
        for (int i=start;i<end;i++){
            checkedListsCount++;
            if (skds.isInBlackListServer(i, ipaddress)){
                HostBlackListsValidator.getHostBlackValidator().blackListOcurrences.add(i);
                ocurrencesCount++;
            }
        }
    }

}
