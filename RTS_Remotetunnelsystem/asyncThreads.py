import asyncio
import threading

class async_thread:	
    def __init__(self,target, *args, **kwargs):
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.thread = threading.Thread(target=self.__run)
        self.thread.start()

    def __run(self):
        self.loop.run_until_complete(self.target(*self.args, **self.kwargs))

    def getThread(self):
        return self.thread
    
    def deamon(self):
        self.thread.daemon = True

    def close(self):
        self.loop.stop()
        self.loop.close()
        
    
