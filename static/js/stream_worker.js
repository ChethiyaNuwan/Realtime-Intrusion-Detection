let eventSource = null;
let currentInterfaceName = null;

self.onmessage = function(e) {
    const data = e.data;

    if (data.interfaceName) {
        if (eventSource) {
            eventSource.close();
            console.log(`Worker: Closed existing EventSource for ${currentInterfaceName}`);
        }
        currentInterfaceName = data.interfaceName;
        console.log(`Worker: Received interface to monitor: ${currentInterfaceName}`);

        if (!!self.EventSource) {
            eventSource = new EventSource(`/stream_packets?interface=${encodeURIComponent(currentInterfaceName)}`);

            eventSource.onmessage = function(event) {
                try {
                    const packetData = JSON.parse(event.data);
                    
                    let parsedTimestamp = parseFloat(packetData.timestamp);
                    const timestamp = !isNaN(parsedTimestamp) ? new Date(parsedTimestamp * 1000).toLocaleTimeString() : 'Unknown';
                    const source = packetData.source || 'Unknown';
                    const destination = packetData.destination || 'Unknown';
                    const protocol = packetData.protocol || 'Unknown';
                    const length = packetData.length || '0';

                    const formattedTimestamp = `[${timestamp}]`.padEnd(15);
                    const formattedSource = `Source: ${source}`.padEnd(25);
                    const formattedDest = `→ Dest: ${destination}`.padEnd(25);
                    const formattedProtocol = `| Protocol: ${protocol}`.padEnd(20);
                    const formattedLength = `| Length: ${length.toString().padStart(5)} bytes`;
                    
                    const packetDetails = `${formattedTimestamp}${formattedSource}${formattedDest}${formattedProtocol}${formattedLength}`;
                    
                    self.postMessage({ type: 'data', payload: packetDetails });
                } catch (error) {
                    console.error("Worker: Error parsing stream data:", error);
                    self.postMessage({ type: 'error', payload: `Error parsing data: ${event.data}` });
                }
            };

            eventSource.onerror = function(errorEvent) {
                console.error(`Worker: EventSource error for ${currentInterfaceName}:`, errorEvent);
                self.postMessage({ type: 'error', payload: `Stream connection error for ${currentInterfaceName}. Attempting to reconnect...` });
                // EventSource attempts to reconnect automatically.
            };

            eventSource.onopen = function() {
                console.log(`Worker: Stream connected for interface: ${currentInterfaceName}`);
                self.postMessage({ type: 'status', payload: `Stream connected for interface: ${currentInterfaceName}` });
            };
        } else {
            console.error("Worker: EventSource not supported in this worker environment.");
            self.postMessage({ type: 'error', payload: 'EventSource not supported in worker.' });
        }
    } else if (data.command === 'close') {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
            console.log(`Worker: EventSource closed for ${currentInterfaceName} by command.`);
        }
        currentInterfaceName = null;
    }
};