// php_direct_input_capture.js
{
    console.log("[PHP_DIRECT_INPUT] Starting direct PHP input capture...");
    
    const config = {
        outputFile: "D:\\utility\\redteam\\frida-server-15.1.14-windows-x86_64.exe\\trace\\php_direct_input.json",
        maxStringLength: 1000
    };

    let traceData = {
        requests: [],
        inputData: [],
        streamOperations: [],
        currentRequest: null,
        startTime: Date.now(),
        requestCount: 0
    };

    function initializeDirectInputCapture() {
        console.log("[DIRECT_INPUT] Setting up direct input capture...");
        
        // Hook request startup to track new requests
        hookRequestStartup();
        
        // Hook input data processing
        hookInputProcessing();
        
        // Hook superglobal population
        hookSuperglobalPopulation();
        
        // Hook stream functions with request context
        hookStreamFunctions();
        
        // Hook specific input readers
        hookInputReaders();
    }

    function hookRequestStartup() {
        const requestFuncs = ["php_request_startup", "sapi_activate"];
        
        requestFuncs.forEach(funcName => {
            let addr = Module.findExportByName(null, funcName);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        traceData.requestCount++;
                        traceData.currentRequest = {
                            id: traceData.requestCount,
                            startTime: Date.now(),
                            method: "UNKNOWN",
                            uri: "",
                            queryString: "",
                            postData: "",
                            rawInput: "",
                            cookies: "",
                            headers: {},
                            superglobals: {
                                _GET: {},
                                _POST: {},
                                _COOKIE: {},
                                _SERVER: {},
                                _FILES: {},
                                _REQUEST: {}
                            },
                            streamOps: []
                        };
                        
                        console.log(`[REQUEST_START] #${traceData.requestCount}`);
                    },
                    onLeave: function(retval) {
                        // Request is fully initialized, capture what we have
                        if (traceData.currentRequest) {
                            traceData.requests.push({...traceData.currentRequest});
                            console.log(`[REQUEST_END] #${traceData.requestCount} - Method: ${traceData.currentRequest.method}`);
                        }
                    }
                });
            }
        });
    }

    function hookInputProcessing() {
        // Hook the main input data processing function
        let treatDataAddr = Module.findExportByName(null, "php_default_treat_data");
        if (treatDataAddr) {
            Interceptor.attach(treatDataAddr, {
                onEnter: function(args) {
                    // args[0] = data string, args[1] = destination array
                    if (traceData.currentRequest && args[0] && !args[0].isNull()) {
                        let data = readNullTerminatedString(args[0], config.maxStringLength);
                        if (data && data.length > 0) {
                            traceData.currentRequest.rawInput = data;
                            console.log(`[RAW_INPUT] ${data.substring(0, 100)}`);
                            
                            traceData.inputData.push({
                                type: "raw_input",
                                request: traceData.requestCount,
                                data: data,
                                timestamp: Date.now() - traceData.startTime
                            });
                        }
                    }
                }
            });
            console.log("[HOOKED] php_default_treat_data");
        }

        // Hook POST data reader
        let readPostAddr = Module.findExportByName(null, "sapi_read_post_data");
        if (readPostAddr) {
            Interceptor.attach(readPostAddr, {
                onEnter: function(args) {
                    if (traceData.currentRequest) {
                        console.log("[POST_READER] Reading POST data");
                    }
                },
                onLeave: function(retval) {
                    if (traceData.currentRequest && retval && !retval.isNull()) {
                        let postData = readNullTerminatedString(retval, config.maxStringLength);
                        if (postData) {
                            traceData.currentRequest.postData = postData;
                            console.log(`[POST_DATA] ${postData.substring(0, 100)}`);
                        }
                    }
                }
            });
        }
    }

    function hookSuperglobalPopulation() {
        // Hook hash table operations to capture superglobal values
        const hashFuncs = ["zend_hash_str_update", "zend_hash_update", "add_assoc_string_ex"];
        
        hashFuncs.forEach(funcName => {
            let addr = Module.findExportByName(null, funcName);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        if (!traceData.currentRequest) return;
                        
                        try {
                            let key = readNullTerminatedString(args[1], 100);
                            let value = readNullTerminatedString(args[2], config.maxStringLength);
                            
                            if (key && value) {
                                let superglobalType = detectSuperglobalFromContext(this.returnAddress);
                                
                                if (superglobalType && traceData.currentRequest.superglobals[superglobalType]) {
                                    traceData.currentRequest.superglobals[superglobalType][key] = value;
                                    
                                    // Special handling for important keys
                                    if (key === "REQUEST_METHOD") {
                                        traceData.currentRequest.method = value;
                                        console.log(`[HTTP_METHOD] ${value}`);
                                    }
                                    if (key === "REQUEST_URI") {
                                        traceData.currentRequest.uri = value;
                                        // Extract query string from URI
                                        if (value.includes('?')) {
                                            traceData.currentRequest.queryString = value.split('?')[1];
                                            traceData.currentRequest.superglobals._GET = parseQueryString(traceData.currentRequest.queryString);
                                        }
                                    }
                                    if (key === "QUERY_STRING") {
                                        traceData.currentRequest.queryString = value;
                                        traceData.currentRequest.superglobals._GET = parseQueryString(value);
                                    }
                                    
                                    console.log(`[SUPERGLOBAL_SET] ${superglobalType}['${key}'] = ${value.substring(0, 50)}`);
                                }
                            }
                        } catch(e) {
                            // Ignore errors
                        }
                    }
                });
            }
        });
    }

    function hookInputReaders() {
        // Hook cookie reader
        let readCookiesAddr = Module.findExportByName(null, "sapi_read_cookies");
        if (readCookiesAddr) {
            Interceptor.attach(readCookiesAddr, {
                onLeave: function(retval) {
                    if (traceData.currentRequest && retval && !retval.isNull()) {
                        let cookies = readNullTerminatedString(retval, config.maxStringLength);
                        if (cookies) {
                            traceData.currentRequest.cookies = cookies;
                            console.log(`[COOKIES] ${cookies.substring(0, 100)}`);
                        }
                    }
                }
            });
        }

        // Hook POST reader specifically
        let postReaderAddr = Module.findExportByName(null, "sapi_module.read_post");
        if (postReaderAddr) {
            Interceptor.attach(postReaderAddr, {
                onEnter: function(args) {
                    console.log("[POST_READ] Starting POST data read");
                }
            });
        }
    }

    function hookStreamFunctions() {
        const streamFuncs = ["_php_stream_fopen", "php_stream_open_wrapper"];
        
        streamFuncs.forEach(funcName => {
            let addr = Module.findExportByName(null, funcName);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        let filename = args[0] ? readNullTerminatedString(args[0], config.maxStringLength) : null;
                        let mode = args[1] ? readNullTerminatedString(args[1], 10) : null;
                        
                        if (filename && isCleanString(filename)) {
                            let streamOp = {
                                type: "stream",
                                function: funcName,
                                filename: filename,
                                mode: mode,
                                timestamp: Date.now() - traceData.startTime,
                                request: traceData.requestCount,
                                inputContext: traceData.currentRequest ? getCurrentInputContext() : null
                            };
                            
                            console.log(`[STREAM] ${funcName}: ${filename}`);
                            traceData.streamOperations.push(streamOp);
                            
                            if (traceData.currentRequest) {
                                traceData.currentRequest.streamOps.push(streamOp);
                            }
                        }
                    }
                });
            }
        });
    }

    function getCurrentInputContext() {
        if (!traceData.currentRequest) return null;
        
        return {
            httpMethod: traceData.currentRequest.method,
            requestUri: traceData.currentRequest.uri,
            queryString: traceData.currentRequest.queryString,
            hasPostData: traceData.currentRequest.postData.length > 0,
            hasCookies: traceData.currentRequest.cookies.length > 0,
            getParams: Object.keys(traceData.currentRequest.superglobals._GET).length > 0 ? 
                       traceData.currentRequest.superglobals._GET : null,
            serverParams: Object.keys(traceData.currentRequest.superglobals._SERVER).length > 0 ?
                         traceData.currentRequest.superglobals._SERVER : null,
            timestamp: Date.now() - traceData.startTime
        };
    }

    function detectSuperglobalFromContext(returnAddress) {
        try {
            let symbol = DebugSymbol.fromAddress(returnAddress);
            if (symbol && symbol.name) {
                let name = symbol.name;
                if (name.includes("_GET")) return "_GET";
                if (name.includes("_POST")) return "_POST";
                if (name.includes("_COOKIE")) return "_COOKIE";
                if (name.includes("_SERVER")) return "_SERVER";
                if (name.includes("_FILES")) return "_FILES";
                if (name.includes("_REQUEST")) return "_REQUEST";
                if (name.includes("_ENV")) return "_ENV";
                
                // Check module name
                let module = Process.findModuleByAddress(returnAddress);
                if (module && module.name.includes("php")) {
                    // Default to _SERVER for unknown PHP module calls
                    return "_SERVER";
                }
            }
        } catch(e) {}
        return null;
    }

    function readNullTerminatedString(ptr, maxLength) {
        if (!ptr || ptr.isNull()) return null;
        
        try {
            let result = "";
            for (let i = 0; i < maxLength; i++) {
                let byte = ptr.add(i).readU8();
                if (byte === 0) break;
                if (byte >= 32 && byte <= 126) {
                    result += String.fromCharCode(byte);
                } else {
                    // Stop at first non-printable character
                    break;
                }
            }
            return result || null;
        } catch(e) {
            return null;
        }
    }

    function parseQueryString(queryString) {
        if (!queryString) return {};
        
        let params = {};
        let pairs = queryString.split('&');
        
        for (let pair of pairs) {
            let [key, value] = pair.split('=');
            if (key) {
                // Basic URL decoding
                try {
                    key = decodeURIComponent(key.replace(/\+/g, ' '));
                    value = value ? decodeURIComponent(value.replace(/\+/g, ' ')) : '';
                    params[key] = value;
                } catch(e) {
                    params[key] = value || '';
                }
            }
        }
        
        return params;
    }

    function isCleanString(str) {
        if (!str) return false;
        // Check if string is mostly printable ASCII
        let printable = 0;
        for (let i = 0; i < Math.min(str.length, 100); i++) {
            let code = str.charCodeAt(i);
            if (code >= 32 && code <= 126) printable++;
        }
        return printable > 0 && (printable / Math.min(str.length, 100)) > 0.7;
    }

    function exportTraceData() {
        console.log("\n[EXPORT] Direct input capture results:");
        console.log(`  Requests: ${traceData.requests.length}`);
        console.log(`  Stream operations: ${traceData.streamOperations.length}`);
        console.log(`  Input data entries: ${traceData.inputData.length}`);
        
        // Show request summary
        let methods = {};
        traceData.requests.forEach(req => {
            methods[req.method] = (methods[req.method] || 0) + 1;
        });
        console.log(`  Methods: ${JSON.stringify(methods)}`);
        
        let output = {
            metadata: {
                timestamp: new Date().toISOString(),
                duration: Date.now() - traceData.startTime,
                totalRequests: traceData.requestCount
            },
            requests: traceData.requests,
            streamOperations: traceData.streamOperations,
            inputData: traceData.inputData,
            currentRequest: traceData.currentRequest
        };
        
        try {
            let file = new File(config.outputFile, "w");
            file.write(JSON.stringify(output, null, 2));
            file.close();
            console.log(`[SAVED] Direct input trace to ${config.outputFile}`);
        } catch(e) {
            console.log(`[SAVE_ERROR] ${e}`);
        }
    }

    // Start capture
    setTimeout(() => {
        initializeDirectInputCapture();
        
        // Export every 20 seconds
        setInterval(exportTraceData, 20000);
        
    }, 1000);

    this.exports = {
        export: exportTraceData,
        stats: () => ({
            requests: traceData.requests.length,
            streams: traceData.streamOperations.length,
            inputs: traceData.inputData.length,
            currentRequest: traceData.currentRequest ? traceData.currentRequest.id : null
        }),
        getCurrentRequest: () => traceData.currentRequest
    };
}