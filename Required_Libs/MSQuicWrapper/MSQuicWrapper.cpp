#include "MSQuicSocket.hpp"
#define PY_SSIZE_T_CLEAN
#include "Python.h" 
#include <cstdio>
#include "msquic.h"

typedef struct {
    PyObject_HEAD
    MSQuicSocket * ptrObj;
} PyMsQuic;

/* Module structure */
static PyModuleDef msquicmodule = {
    PyModuleDef_HEAD_INIT, 
    "msquic", /* name of module */
    "A MSQuicSocket module", /* Doc string (may be NULL) */
    -1, /* Size of per-interpreter state or -1 */
    //MsQuicMethods /* Method table */
    NULL, NULL, NULL, NULL, NULL
}; 

static int Pymsquic_init(PyMsQuic *self, PyObject *args, PyObject *kwds) {
    self->ptrObj=new MSQuicSocket();
    return 0;
}

static void Pymsquic_dealloc(PyMsQuic *self) {
    delete self->ptrObj;
    Py_TYPE(self)->tp_free(self);
}

static PyObject *Pymsquic_ServerSocket(PyMsQuic *self, PyObject *args){
    uint UDPport;
    if (!PyArg_ParseTuple(args, "i", &UDPport))
        return NULL;        
    int retval;
    retval = (self->ptrObj)->CreateServerSocket(UDPport);
    return Py_BuildValue("i", retval);
}

static PyObject *Pymsquic_ClientSocket(PyMsQuic *self, PyObject *args){
    const char * add;
    uint UDPport;
    uint64_t IdleTimeout;
    if (!PyArg_ParseTuple(args, "sii", &add, &UDPport, &IdleTimeout))
        return NULL;  
    int retval;
    std::string address = add;
    std::cout<<address<<"  " <<UDPport<<std::endl;
    (self->ptrObj)->CreateClientSocket(address, UDPport, IdleTimeout);
    retval = (self->ptrObj)->checkConnection();
    return Py_BuildValue("i", retval);
}

static PyObject *Pymsquic_RecvFrom(PyMsQuic *self, PyObject *args){
    InboundMsg retval;
    Py_BEGIN_ALLOW_THREADS
    retval = (self->ptrObj)->getMsgBlocking();
    Py_END_ALLOW_THREADS
    uint64_t stream_id = (uint64_t)(uintptr_t)retval.stream;
    return Py_BuildValue("y#K", retval.data.data(), (Py_ssize_t)retval.data.size(), stream_id);
}

static PyObject *Pymsquic_RecvNow(PyMsQuic *self, PyObject *args){
    InboundMsg msg;
    if (!self->ptrObj->tryGetMsg(msg)) {
        return Py_BuildValue("y#K", "", 0, (uint64_t)0);
    }
    uint64_t stream_id = (uint64_t)(uintptr_t)msg.stream;
    return Py_BuildValue("y#K", msg.data.data(), (Py_ssize_t)msg.data.size(), stream_id);
}

static PyObject *Pymsquic_ClientSend(PyMsQuic *self, PyObject *args){
    const char * bytes;
    Py_ssize_t length;
    if (!PyArg_ParseTuple(args, "s#", &bytes, &length))
        return NULL;    
    std::cout<<"The length "<<length<<std::endl;
    (self->ptrObj)->ClientSend( (self->ptrObj)->connections.back(), bytes, length); 
    return Py_BuildValue("i", 1);
}

static PyObject *Pymsquic_ClientSendMessage(PyMsQuic *self, PyObject *args){
    const char * bytes;
    uint32_t length;
    if (!PyArg_ParseTuple(args, "yi", &bytes, &length))
        return NULL;    
    (self->ptrObj)->ClientSend( (self->ptrObj)->connections.back(), bytes, length); 
    return Py_BuildValue("i", 1);
}

static PyObject *Pymsquic_ServerSend(PyMsQuic *self, PyObject *args){
    unsigned long long stream_id;
    const char * bytes;
    Py_ssize_t length;
    if (!PyArg_ParseTuple(args, "Ks#", &stream_id, &bytes, &length))
        return NULL;

    HQUIC stream = (HQUIC)(uintptr_t)stream_id;
    self->ptrObj->ServerSend(stream, bytes, (uint32_t)length);
    return Py_BuildValue("i", 1); 
}


static PyObject *Pymsquic_ServerSendMessage(PyMsQuic *self, PyObject *args){
    const char * bytes;
    uint32_t length;
     int currentStreamID; 
    if (!PyArg_ParseTuple(args, "iyi",  &currentStreamID, &bytes, &length))
        return NULL;    
    (self->ptrObj)->ServerSend( (self->ptrObj)->currentStreams[currentStreamID], bytes, length);
    return Py_BuildValue("i", 1);
}


static PyObject *Pymsquic_RecvAny(PyMsQuic *self, PyObject *args){
    InboundMsg retval;
    Py_BEGIN_ALLOW_THREADS
    retval = (self->ptrObj)->getMsgBlocking();
    Py_END_ALLOW_THREADS
    uint64_t stream_id = (uint64_t)(uintptr_t)retval.stream;
    return Py_BuildValue("y#K", retval.data.data(), (Py_ssize_t)retval.data.size(), stream_id);

}

/* Module method table */
static PyMethodDef msquicMethods[] = { 
    {"CreateServerSocket", (PyCFunction)Pymsquic_ServerSocket, METH_VARARGS, "Run the Server"}, 
    {"CreateClientSocket", (PyCFunction)Pymsquic_ClientSocket, METH_VARARGS, "Run the Client"}, 
    {"RecvFrom", (PyCFunction)Pymsquic_RecvFrom, METH_VARARGS, "Recv data"}, 
    {"RecvFromNow", (PyCFunction)Pymsquic_RecvNow, METH_VARARGS, "Recv data, nonblocking only checks once"}, 
    {"ClientSend", (PyCFunction)Pymsquic_ClientSend, METH_VARARGS, "Send the data"}, 
    {"ClientSendMessage", (PyCFunction)Pymsquic_ClientSendMessage, METH_VARARGS, "Send the data"}, 
    {"ServerSend", (PyCFunction)Pymsquic_ServerSend, METH_VARARGS, "Send the data"}, 
    {"ServerSendMessage", (PyCFunction)Pymsquic_ServerSendMessage, METH_VARARGS, "Send the data"}, 
    {"RecvAny", (PyCFunction)Pymsquic_RecvAny, METH_VARARGS, "Recv data from any source"}, 

    { NULL} 
}; 

static PyTypeObject PymsquicType = { PyVarObject_HEAD_INIT(NULL, 0) 
                                    "msquic.MSQuicSocket" };
  
/* Module initialization function */
PyMODINIT_FUNC PyInit_msquic(void) { 
    PyObject *m;
    PymsquicType.tp_new = PyType_GenericNew;
    PymsquicType.tp_basicsize=sizeof(PyMsQuic);
    PymsquicType.tp_dealloc=(destructor) Pymsquic_dealloc;
    PymsquicType.tp_flags=Py_TPFLAGS_DEFAULT;
    PymsquicType.tp_doc="PyMsQuic objects";
    PymsquicType.tp_methods=msquicMethods;
    PymsquicType.tp_init=(initproc)Pymsquic_init;

    if (PyType_Ready(&PymsquicType) < 0)
        return NULL;

    m = PyModule_Create(&msquicmodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&PymsquicType);
    PyModule_AddObject(m, "MSQuicSocket", (PyObject*)&PymsquicType);
    return m;
} 