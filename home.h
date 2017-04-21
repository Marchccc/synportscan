#ifndef HOME_H
#define HOME_H

#include <QMainWindow>

namespace Ui {
class Home;
}

class Home : public QMainWindow
{
    Q_OBJECT

public:
    explicit Home(QWidget *parent = 0);
    ~Home();

private slots:
    void on_pushButton_clicked();

public:
//    void ChangUis(std::string str);//提供的自定义改变UI的方法
    static Home *m_pHome;
    Ui::Home *ui;

private:
//    Ui::Home *ui;
};

#endif // HOME_H
