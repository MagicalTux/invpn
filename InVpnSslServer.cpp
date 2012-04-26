#include "InVpnSslServer.hpp"

void InVpnSslServer::incomingConnection(int socketDescriptor) {
	QSslSocket *serverSocket = new QSslSocket(this);
	if (serverSocket->setSocketDescriptor(socketDescriptor)) {
		ready(serverSocket);
	} else {
		delete serverSocket;
	}
}
