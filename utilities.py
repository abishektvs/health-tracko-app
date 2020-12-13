from random import randint

def generate_otp():
    otp = ''
    for _ in range(0,5):
        otp += str(randint(0,9))

    return otp

def stringify_datetime(datetime_obj):

    time = datetime_obj.strftime("%H:%M:%S")
    date = datetime_obj.strftime("%m/%d/%Y")
    
    return date, time

def status_of_bmi(bmi):
    if bmi < 18.5:
            status = "Under weight"
            status_pic = "static\images\BMIstatusPics\lean.png" 
    elif 18.5 <= bmi <= 24.9:
        status = "Fit"
        status_pic = r"static\images\BMIstatusPics\fit.jpg"
    elif 25 <= bmi <= 29.9: 
        status = "Over weight"
        status_pic = "static\images\BMIstatusPics\overweight.png"
    elif 30.0 <= bmi <= 34.9:
        status = "Obesity stage 1 - High risk"
        status_pic = "static\images\BMIstatusPics\obese.jpg"
    elif 35 <= bmi <= 40:
        status = "Obesity stage 2 - Very High risk"
        status_pic = "static\images\BMIstatusPics\obese.jpg"
    elif bmi > 40:
        status = "Obesity stage 3 - Extreme Risk"
        status_pic = "static\images\BMIstatusPics\obeserisk.png"
    else:
        status, status_pic = "bmi error", "errorpic"
    
    return status, status_pic

def analyze_health(user_answers):
    user_answers = dict(user_answers)
    user_result = {}
    answer_scores = {
        'q1' : {'q1a1':'Drinking 4 litres of water every day is great keep it up !.',
                'q1a2':'It is good to drink water atleasy 4 litres a day, which helps you to keep brisk and hydrated.',
                'q1a3':'Drinking water helps to maintain the balance of body fluids. So develop the habit of drinking water atleast 4 litres a day.'
                },
        'q2' : {'q2a1':'Sleeping before 10 is very good which helps maintaing your health.', 
                'q2a2':'Sleeping before 10 is very good which helps maintaing your health, so better try to sleep soon.',
                'q2a3':'Sleeping before 10 is very good which helps maintaing your health, so better try to sleep before 10. It helps to wake early with fresh mind.',
                'q2a4':'This is very bad to health sleeping after 2 am. Sleeping before 10 is very good which helps maintaing your health, so better try to sleep before 10. It helps to wake early with fresh mind.'
                }, 
        'q3' : {'q3a1':'Maintaing your sleeping cyle is excellent which results in good body health.', 
                'q3a2':'Maintaing your sleeping cyle is very much important. This helps you to sleep early and maintain good health.'
                },
        'q4' : {'q4a1':'Try not to use mobile phones before sleep which could damage your eye sight.',
                'q4a2':'Good that you are not using mobile phones, if honest it\'s very good habit',
                'q4a3':'Better you try to stop using mobile phones before sleep, This helps you to get good sleep'
                },
        'q5' : {'q5a1':'Junk foods are very bad to health so reduce eating them.',
                'q5a2':'Fast foods have very bad effect on your stomach and livers. Reduce eating fast foods and junk foods.',
                'q5a3':'Home made recipies are delicious and good to health unless your sister interferes(lol) and Home made recipies are mom\'s magic.'
                },
        'q6' : {'q6a1':'Yoga helps your body to maintain fitness so start atleast of 15 mins a day with yoga.',
                'q6a2':'Yoga helps your body to maintain fitness so start atleast of 15 mins a day with yoga.',
                'q6a3':'Praciting yoga and gym is very good. Yoga helps your body to maintain fitness.'
                },
        'q7' : {'q7a1':'Improve you health using above suggestions which helps you from often sickness.',
                'q7a2':'Improve you health using above suggestions which helps you from often sickness.',
                'q7a3':'Staying strong even during weather changes portrays your good habits.'
                },
    }

    for question in user_answers.keys():
        answer = user_answers[question]
        user_result[question] = (answer_scores[question][answer])
    
    return user_result
