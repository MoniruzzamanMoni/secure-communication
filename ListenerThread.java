
class ListenerThread extends Thread {
	Terminal t1;
    public ListenerThread(Terminal _t1) {
    	t1 = _t1;
    }
    public void run() {
    	while(!t1.exitFlug) {
    		t1.startListen();
    		//t1.encryptTextBy3DESKey();
            try {
            	sleep((int)(1000));
		    } catch (InterruptedException e) {}
    	}
    }
}
