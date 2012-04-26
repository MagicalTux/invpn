#include "InVpnNode.hpp"
#include "InVpn.hpp"

InVpnNode::InVpnNode(InVpn *_parent, const QByteArray &_mac): QObject(_parent) {
	parent = _parent;
	mac = _mac;
	link = NULL;
}

bool InVpnNode::setLink(QSslSocket *_link) {
	if (link != NULL) return false;
	link = _link;
	// TODO connect stuff
	return true;
}

void InVpnNode::push(const QByteArray&msg) {
	if (link == NULL) return;
	link->write(msg);
}
