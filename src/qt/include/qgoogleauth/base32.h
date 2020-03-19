#ifndef BASE32_H
#define BASE32_H

#include <QObject>

class Base32 : public QObject
{
    Q_OBJECT
public:
    explicit Base32(QObject *parent = 0);
    static int base32_decode(const quint8 *encoded, quint8 *result, int bufSize);
    
Q_SIGNALS:
    
public Q_SLOTS:
    
};

#endif // BASE32_H
