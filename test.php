function Action_TopMenuGets($NewLoc) {
  //Function to Action GET requests from Top Menu
  //Return value false when no action carried out
  //1. Is _GET['a'] (action) set?
  //2a. Delete config out of Memcached
  //2b. Execute appropriate action
  //2c. In the case of Restart or Shutdown we want to delay execution of the command for a couple of seconds to finish off any disk writes
  //2d. For any other value of 'a' leave this function and carry on with previous page
  //3. Sleep for 5 seconds to prevent a Race Condition occuring where new config could be loaded before ntrk-pause has been able to modify /etc/notrack/notrack.conf
  //   5 seconds is too much for an x86 based server, but for a Raspberry Pi 1 its just enough.
  //4. Load new page (usually reload current page), to dump GET['a'] and prevent user from refreshing and repeating function.

  if (isset($_GET['a'])) {
    $Mem->delete('Config');
    switch ($_GET['a']) {
      case 'pause5':
        ExecAction('pause5', true, true);
        break;
      case 'pause15':
        ExecAction('pause15', true, true);
        break;
      case 'pause30':
        ExecAction('pause30', true, true);
        break;
      case 'pause60':
        ExecAction('pause60', true, true);
        break;    
      case 'start':
        ExecAction('start', true, true);
        break;
      case 'stop':
        ExecAction('stop', true, true);
        break;
      case 'force-notrack':
        ExecAction('force-notrack', true, true);
        break;
      case 'restart':
        sleep(2);
        ExecAction('restart', true, true);
        exit(0);
        break;
      case 'shutdown':
        sleep(2);
        ExecAction('shutdown', true, true);
        exit(0);
        break;
      default:
        return false;
    }
  sleep(5);
  header('Location '.$NewLoc);
  
  return false;
}
